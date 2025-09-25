import asyncio
import ipaddress
import json
import logging
import sys
import time
import traceback
import csv

from argparse import ArgumentParser
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from functools import partial
from math import floor
from typing import Type

from .bacnet_utils import make_jsonable, _handle_bacnet_response
from .cache_handler import (_clear_cache_for_device, _get_cached_object_list, _get_cache_stats,
                            load_cached_object_properties, save_object_properties)

from bacpypes3.app import Application
from bacpypes3.basetypes import DateTime, PropertyReference
from bacpypes3.constructeddata import AnyAtomic
from bacpypes3.lib.batchread import BatchRead, DeviceAddressObjectPropertyReference
from bacpypes3.pdu import Address, PDUData
from bacpypes3.apdu import (ConfirmedPrivateTransferACK, ConfirmedPrivateTransferError, ConfirmedPrivateTransferRequest,
                            ErrorRejectAbortNack, TimeSynchronizationRequest, AbortPDU, ErrorPDU, RejectPDU)
from bacpypes3.primitivedata import ClosingTag, Date, Null, ObjectIdentifier, ObjectType, OpeningTag, Tag, TagList, \
    Time, PropertyIdentifier
from bacpypes3.vendor import get_vendor_info

from protocol_proxy.ipc import callback, ProtocolProxyMessage
from protocol_proxy.proxy import launch
from protocol_proxy.proxy.asyncio import AsyncioProtocolProxy
from protocol_proxy.protocol.bacnet.logging_utils import _log

from .json import serialize

logging.basicConfig(filename='/tmp/bacnet_proxy.log',
                    level=logging.DEBUG,
                    format='%(asctime)s - %(message)s')

@dataclass
class COVSubscription:
    address: str
    object_identifier: str
    confirmed: bool | None
    lifetime: bool | None
    stop_event: asyncio.Event = asyncio.Event()

    def is_unchanged(self, address: str, object_identifier: str, confirmed: bool | None, lifetime: bool | None) -> bool:
        return (address == self.address and object_identifier == self.object_identifier
                and confirmed == confirmed and lifetime == lifetime)

class BACnetProxy(AsyncioProtocolProxy):
    def __init__(self, local_device_address, bacnet_network=0, vendor_id=999, object_name='VOLTTRON BACnet Proxy',
                 **kwargs):
        _log.debug('IN BACNETPROXY __init__')
        super(BACnetProxy, self).__init__(**kwargs)
        self.bacnet = BACnet(local_device_address, bacnet_network, vendor_id, object_name, **kwargs)
        self.loop = asyncio.get_event_loop()
        
        # Cache for object-list to avoid re-reading on every page request
        # Format: {device_key: (object_list, timestamp)}
        self._object_list_cache = {}
        self._cache_timeout = 300
        self._subscribed_cov: dict[str, COVSubscription] = {}

        self.register_callback(self.batch_read_endpoint, 'BATCH_READ', provides_response=True)
        self.register_callback(self.confirmed_private_transfer_endpoint, 'CONFIRMED_PRIVATE_TRANSFER', provides_response=True)
        self.register_callback(self.cov_setup_endpoint, 'SETUP_COV', provides_response=False)
        self.register_callback(self.cov_cancel_endpoint, 'CANCEL_COV', provides_response=False)
        self.register_callback(self.query_device_endpoint, 'QUERY_DEVICE', provides_response=True)
        self.register_callback(self.read_property_endpoint, 'READ_PROPERTY', provides_response=True)
        self.register_callback(self.read_property_multiple_endpoint, 'READ_PROPERTY_MULTIPLE', provides_response=True)
        self.register_callback(self.time_synchronization_endpoint, 'TIME_SYNCHRONIZATION', provides_response=True)
        self.register_callback(self.send_object_user_lock_time_endpoint, 'SEND_OBJECT_USER_LOCK_TIME', provides_response=True)
        self.register_callback(self.write_property_endpoint, 'WRITE_PROPERTY', provides_response=True)
        self.register_callback(self.read_device_all_endpoint, 'READ_DEVICE_ALL', provides_response=True)
        self.register_callback(self.who_is_endpoint, 'WHO_IS', provides_response=True)
        self.register_callback(self.scan_subnet_endpoint, 'SCAN_SUBNET', provides_response=True, timeout=300)
        self.register_callback(self.read_object_list_names_endpoint, 'READ_OBJECT_LIST_NAMES', provides_response=True, timeout=300)
        self.register_callback(self.read_object_list_names_endpoint, 'READ_OBJECT_LIST', provides_response=True, timeout=300)
        self.register_callback(self.clear_cache_endpoint, 'CLEAR_CACHE', provides_response=True)
        self.register_callback(self.get_cache_stats_endpoint, 'GET_CACHE_STATS', provides_response=True)

    @callback
    async def batch_read_endpoint(self, _, raw_message: bytes):
        """Endpoint to gracefully handle read multiple with fallback to single reads."""
        message = json.loads(raw_message.decode('utf8'))
        address = message['device_address']
        read_specifications = message['read_specifications']
        result = await self.bacnet.batch_read(address, read_specifications)
        return serialize(result)

    @callback
    async def confirmed_private_transfer_endpoint(self, _, raw_message: bytes):
        """Endpoint for confirmed private transfer."""
        message = json.loads(raw_message.decode('utf8'))
        address = Address(message['address'])
        vendor_id = message['vendor_id']
        service_number = message['service_number']
        # TODO: from_json may be an AI hallucination. Need to check this.
        service_parameters = TagList.from_json(message.get('service_parameters', []))
        result = await self.bacnet.confirmed_private_transfer(address, vendor_id, service_number, service_parameters)
        return serialize(result)

    async def cov_callback_function(self, peer, key, value):
        message = ProtocolProxyMessage(
            method_name='RECEIVE_COV',
            payload=serialize({key: value})
            )
        _log.debug(f'@@@@@@ SENDING COV CALLBACK: {message}')
        await self.send(peer, message)

    @callback
    async def cov_setup_endpoint(self, headers, raw_message: bytes):
        """Endpoint for starting or modifying change of value subscription."""
        peer = self.peers.get(headers.sender_id)
        message = json.loads(raw_message.decode('utf8'))
        key = message['subscription_key']
        address = message['device_address']
        object_identifier = message['monitored_object_identifier']
        property_identifier = message['property_identifier']
        confirmed = message['issue_confirmed_notifications']
        lifetime = message['lifetime']
        if existing := self._subscribed_cov.get(key):
            if existing.is_unchanged(address, object_identifier, confirmed, lifetime):
                return
            else:
                existing.stop_event.set()
                self._subscribed_cov.pop(key)
        # TODO: What happens if remote has existing subscription that was lost on this end?
        self._subscribed_cov[key] = COVSubscription(address, object_identifier, confirmed, lifetime)
        cov_callback = partial(self.cov_callback_function, peer, key)
        self.loop.create_task(self.bacnet.change_of_value(device_address=address, object_identifier=object_identifier,
                                          process_identifier=None, confirmed=confirmed, lifetime=lifetime,
                                          stop_event=self._subscribed_cov[key].stop_event, cov_callback=cov_callback,
                                                          property_identifier=property_identifier
                                                          ))

    @callback
    async def cov_cancel_endpoint(self, _, raw_message: bytes):
        message = json.loads(raw_message.decode('utf8'))
        key = message['subscription_key']
        if existing := self._subscribed_cov.pop(key):
            existing.stop_event.set()

    @callback
    async def query_device_endpoint(self, _, raw_message: bytes):
        """Endpoint for querying a device."""
        message = json.loads(raw_message.decode('utf8'))
        address = message['address']
        property_name = message.get('property_name', 'object-identifier')
        result = await self.bacnet.query_device(address, property_name)
        return serialize(result)

    @callback
    async def read_property_endpoint(self, _, raw_message: bytes):
        """Endpoint for reading a property from a BACnet device."""
        message = json.loads(raw_message.decode('utf8'))
        address = message['device_address']
        object_identifier = message['object_identifier']
        property_identifier = message['property_identifier']
        property_array_index = message.get('property_array_index', None)
        result = await self.bacnet.read_property(address, object_identifier, property_identifier, property_array_index)
        return serialize(result)

    @callback
    async def read_property_multiple_endpoint(self, _, raw_message: bytes):
        """Endpoint for reading multiple properties from a BACnet device."""
        message = json.loads(raw_message.decode('utf8'))
        address = message['device_address']
        read_specifications = message['read_specifications']
        result = await self.bacnet.read_property_multiple(address, read_specifications)
        return serialize(result)

    @callback
    async def send_object_user_lock_time_endpoint(self, _, raw_message: bytes):
        """Endpoint for sending an object user lock time to a BACnet device."""
        message = json.loads(raw_message.decode('utf8'))
        address = Address(message['address'])
        device_id = message['device_id']
        object_id = message['object_id']
        lock_interval = message['lock_interval']
        result = await self.bacnet.send_object_user_lock_time(address, device_id, object_id, lock_interval)
        return serialize(result)

    @callback
    async def time_synchronization_endpoint(self, _, raw_message: bytes):
        """Endpoint for setting time on a BACnet device."""
        message = json.loads(raw_message.decode('utf8'))
        address = Address(message['address'])
        date_time = datetime.fromisoformat(message['date_time']) if hasattr(message, 'date_time') else None
        result = await self.bacnet.send_object_user_lock_time(address, date_time)
        return serialize(result)

    @callback
    async def write_property_endpoint(self, _, raw_message: bytes):
        """Endpoint for writing a property to a BACnet device."""
        message = json.loads(raw_message.decode('utf8'))
        address = message['device_address']
        object_identifier = message['object_identifier']
        property_identifier = message['property_identifier']
        value = message['value']
        priority = message['priority']
        property_array_index = message.get('property_array_index', None)
        result = await self.bacnet.write_property(address, object_identifier, property_identifier, value, priority,
                                            property_array_index)
        return serialize(result)

    @callback
    async def write_property_multiple_endpoint(self, _, raw_message: bytes):
        """Endpoint for writing multiple properties to a BACnet device."""
        message = json.loads(raw_message.decode('utf8'))
        address = message['device_address']
        write_specifications = message['write_specifications']
        result = await self.bacnet.write_property_multiple(address, write_specifications)
        return serialize(result)

    @callback
    async def read_device_all_endpoint(self, _, raw_message: bytes):
        """Endpoint for reading all properties from a BACnet device."""
        try:
            message = json.loads(raw_message.decode('utf8'))
            device_address = message['device_address']
            device_object_identifier = message['device_object_identifier']
            result = await self.bacnet.read_device_all(device_address, device_object_identifier)
            # if not result:  # TODO: Is there really a good reason to fill in a value here? This isn't really an error.
            #     return json.dumps({"error": "No data returned from read_device_all"}).encode('utf8')
            return serialize(result)
        except Exception as e:
            # TODO: Should we handle this with serialize, instead?
            tb = traceback.format_exc()
            return json.dumps({"error": str(e), "traceback": tb}).encode('utf8')

    @callback
    async def who_is_endpoint(self, _, raw_message: bytes):
        """Endpoint for WHO-IS discovery."""
        message = json.loads(raw_message.decode('utf8'))
        device_instance_low = message.get('device_instance_low', 0)
        device_instance_high = message.get('device_instance_high', 4194303)
        dest = message.get('dest', '255.255.255.255:47808')
        apdu_timeout = message.get('apdu_timeout', None)  # Keep for backward compatibility but don't use  # TODO: Why!?
        result = await self.bacnet.who_is(device_instance_low, device_instance_high, dest)
        return serialize(result)

    @callback
    async def scan_subnet_endpoint(self, _, raw_message: bytes):
        """Endpoint for subnet scanning.
           Input JSON (all optional except network):
             {
               "network": "192.168.1.0/24",
               "whois_timeout": 2.0,
               "port": 47808,
               "low_id": 0,
               "high_id": 4194303,
               "enable_brute_force": true,
               "semaphore_limit": 20,
               "max_duration": 280.0
             }
           Note: Removed force_fresh_scan - scan is always real but cache-informed.
        """
        try:
            message = json.loads(raw_message.decode('utf8'))
            network_str = message['network']
            whois_timeout = float(message.get('whois_timeout', 2.0))
            port = int(message.get('port', 47808))
            low_id = int(message.get('low_id', 0))
            high_id = int(message.get('high_id', 4194303))
            enable_brute_force = bool(message.get('enable_brute_force', True))
            semaphore_limit = int(message.get('semaphore_limit', 20))
            max_duration = float(message.get('max_duration', 280.0))

            # Removed force_fresh_scan parameter
            result = await self.bacnet.scan_subnet(network_str,
                                                   whois_timeout=whois_timeout,
                                                   port=port,
                                                   low_id=low_id,
                                                   high_id=high_id,
                                                   enable_brute_force=enable_brute_force,
                                                   semaphore_limit=semaphore_limit,
                                                   max_duration=max_duration)
            return json.dumps(result).encode('utf8')
        except Exception as e:
            _log.error(f"scan_subnet_endpoint error: {e}")
            return json.dumps({"error": str(e)}).encode('utf8')

    @callback
    async def read_object_list_names_endpoint(self, _, raw_message: bytes):
        """Endpoint for reading object-list and object-names from a BACnet device with pagination and caching."""
        try:
            message = json.loads(raw_message.decode('utf8'))
            device_address = message['device_address']
            device_object_identifier = message['device_object_identifier']
            page = message.get('page', 1)
            page_size = message.get('page_size', 100)
            force_fresh_read = message.get('force_fresh_read', False)

            logging.getLogger(__name__).info(
                f"read_object_list_names_endpoint called for device {device_address}, page {page}, page_size {page_size}, force_fresh_read={force_fresh_read}"
            )

            # Check if the BACnet application is still connected
            if not hasattr(self.bacnet, 'app') or self.bacnet.app is None:
                return json.dumps({
                    "status": "error",
                    "error": "BACnet application not available"
                }).encode('utf8')

            result = await self.bacnet.read_object_list_names_paginated(
                device_address, device_object_identifier, page, page_size, force_fresh_read,
                self._object_list_cache, self._cache_timeout)

            logging.getLogger(__name__).info(
                f"read_object_list_names_paginated returned response with status: {result.get('status')}"
            )

            # Check for error in the result
            if result.get('status') == 'error':
                logging.getLogger(__name__).error(
                    f"Error in read_object_list_names_paginated: {result['error']}")
                return json.dumps(result).encode('utf8')

            # Make the results jsonable using the unified method
            if 'results' in result:
                jsonable_results = {}
                for obj_id, properties in result['results'].items():
                    if isinstance(properties, dict):
                        processed_properties = {}
                        for prop_name, prop_value in properties.items():
                            # Set context for units conversion
                            if prop_name == 'units' and isinstance(prop_value, int):
                                # Handle units specifically - try to convert to EngineeringUnits
                                try:
                                    from bacpypes3.basetypes import EngineeringUnits
                                    engineering_unit = EngineeringUnits(prop_value)
                                    unit_str = str(engineering_unit)
                                    if unit_str.startswith(
                                            'EngineeringUnits(') and unit_str.endswith(')'):
                                        processed_properties[prop_name] = unit_str[
                                            17:-1]    # Remove "EngineeringUnits(" and ")"
                                    else:
                                        processed_properties[prop_name] = unit_str
                                    logging.getLogger(__name__).debug(
                                        f"Converted units {prop_value} to {processed_properties[prop_name]} for {obj_id}"
                                    )
                                except (ImportError, ValueError, TypeError) as e:
                                    logging.getLogger(__name__).warning(
                                        f"Failed to convert units {prop_value} for {obj_id}: {e}")
                                    processed_properties[prop_name] = make_jsonable(prop_value)
                            else:
                                # Use unified make_jsonable for all other properties
                                processed_properties[prop_name] = make_jsonable(prop_value)
                        jsonable_results[str(obj_id)] = processed_properties
                    else:
                        jsonable_results[str(obj_id)] = make_jsonable(properties)
                result['results'] = jsonable_results

            return json.dumps(result).encode('utf8')
        except Exception as e:
            tb = traceback.format_exc()
            logging.getLogger(__name__).error(
                f"Exception in read_object_list_names_endpoint: {e}\n{tb}")
            return json.dumps({"status": "error", "error": str(e), "traceback": tb}).encode('utf8')

    @callback
    async def clear_cache_endpoint(self, _, raw_message: bytes):
        """Endpoint for clearing cache."""
        message = json.loads(raw_message.decode('utf8'))
        device_address = message.get('device_address', None)
        device_object_identifier = message.get('device_object_identifier', None)

        if device_address:
            _clear_cache_for_device(device_address, device_object_identifier)
            result = {"status": "success", "message": f"Cache cleared for device {device_address}"}
        else:
            self._object_list_cache.clear()
            result = {"status": "success", "message": "All cache cleared"}

        return json.dumps(result).encode('utf8')

    @callback
    async def get_cache_stats_endpoint(self, _, raw_message: bytes):
        """Endpoint for getting cache statistics."""
        result = _get_cache_stats()
        return json.dumps(result).encode('utf8')
    
    #TODO Fix
    @callback
    async def get_cached_devices_endpoint(self, _, raw_message: bytes):
        """New endpoint specifically for retrieving cached devices without scanning."""
        try:
            message = json.loads(raw_message.decode('utf8'))
            network_str = message.get('network', None)    # Optional network filter

            cached_devices = self.bacnet.load_cached_devices(network_str)
            return json.dumps(cached_devices).encode('utf8')
        except Exception as e:
            _log.error(f"get_cached_devices_endpoint error: {e}")
            return json.dumps({"error": str(e)}).encode('utf8')

    @classmethod
    def get_unique_remote_id(cls, unique_remote_id: tuple) -> tuple:
        """Get a unique identifier for the proxy server
         given a unique_remote_id and protocol-specific set of parameters."""
        return unique_remote_id[0:2]  # TODO: How can we know what the first two params really are?
                                      #  (Ideally they are address and port.)
                                      #  Consider named tuple?
                                      
class BACnet:
    def __init__(self, local_device_address, bacnet_network=0, vendor_id=999, object_name='VOLTTRON BACnet Proxy',
                 device_info_cache=None, router_info_cache=None, ase_id=None, **_):
        _log.debug('WELCOME BAC')
        vendor_info = get_vendor_info(vendor_id)
        device_object_class = vendor_info.get_object_class(ObjectType.device)
        device_object = device_object_class(objectIdentifier=('device', vendor_id), objectName=object_name)
        network_port_object_class = vendor_info.get_object_class(ObjectType.networkPort)
        network_port_object = network_port_object_class(local_device_address,
                                                        objectIdentifier=("network-port", bacnet_network),
                                                        objectName="NetworkPort-1", networkNumber=bacnet_network,
                                                        networkNumberQuality="configured")
        self.app = Application.from_object_list(
            [device_object, network_port_object],
            device_info_cache=device_info_cache,  # TODO: If these should be passed in, add to args & launch.
            router_info_cache=router_info_cache,
            aseID=ase_id
        )
        _log.debug(f'WE HAVE AN APP: {self.app.device_info_cache}')

    async def query_device(self, address: str, property_name: str = 'object-identifier'):
        """Returns properties about the device at the given address.
            If a different property name is not given, this will be the object-id.
            This function allows unicast discovery.
            This can get everything from device if it is using read_property_multiple and ALL
        """
        _log.debug('IN QUERY DEVICE METHOD')
        return await self.read_property(device_address=address, object_identifier='device:4194303',
                                        property_identifier=property_name)

    async def batch_read(self, device_address: str, read_specifications: dict[str, dict]):
        daopr_list = [
            DeviceAddressObjectPropertyReference(
                key=key,
                device_address=device_address,
                object_identifier=spec['object_id'],
                property_reference=(spec['property'], spec['array_index'])
                    if spec['array_index'] is not None else spec['property']
            ) for key, spec in read_specifications.items()
        ]
        results = {}
        batch = BatchRead(daopr_list)
        # run until the batch is done
        await batch.run(self.app, lambda k, v: results.update({k: v}))
        return results

    async def change_of_value(self, device_address: str, object_identifier: str, process_identifier: int | None,
                              confirmed: bool | None, lifetime: bool | None,
                              stop_event: asyncio.Event, cov_callback: Callable, property_identifier: str = None):
        try:
            property_identifier = PropertyIdentifier(property_identifier)
            async with self.app.change_of_value(
                    Address(device_address), ObjectIdentifier(object_identifier),
                    process_identifier, confirmed, int(lifetime)  # TODO: The context manager should be refreshing automatically. Is it?
            ) as scm:
                while not stop_event.is_set():
                    received_property_identifier, property_value = await scm.get_value()
                    if not property_identifier or property_identifier == received_property_identifier:
                        await cov_callback(property_value)
                # Cancel subscription on stop_event.
                scm.issue_confirmed_notifications = None
                scm.lifetime = None
                scm.refresh_subscription()
        except Exception as e:
            _log.warning(f"Exception handling COV: {e}")

    async def read_property(self, device_address: str, object_identifier: str, property_identifier: str,
                   property_array_index: int | None = None):
        try:
            _log.debug(f"BACnet.read_property called with device_address={device_address}, object_identifier={object_identifier}, property_identifier={property_identifier}, property_array_index={property_array_index}")
            response = await self.app.read_property(
                Address(device_address),
                ObjectIdentifier(object_identifier),
                property_identifier,
                int(property_array_index) if property_array_index is not None else None
            )
            _log.debug(f"BACnet.read_property response: {response}")
        except ErrorRejectAbortNack as err:
            _log.debug(f'Error reading property {err}')
            response = err
        if isinstance(response, AnyAtomic):
            response = response.get_value()
        _log.debug(f"BACnet.read_property final response: {response}")
        return response

    async def read_property_multiple(self, device_address: str, read_specifications: dict):
        try:  # TODO: Do we need to fall back to read_property in loop? How to detect that? Should it be in driver instead?
            _log.debug(f'Reading one or more properties at {device_address}: {read_specifications}')
            # spec_list = []
            # for (object_id, property_id, property_array_index) in read_specifications.values():
            #     spec_list.extend([
            #         ObjectIdentifier(object_id),
            #         property_id])
            #     if property_array_index is not None:
            #         spec_list.append(int(property_array_index))
            response = await self.app.read_property_multiple(
                Address(device_address),
                ['analogInput, 3000741',  # TODO: This is hard coded for testing. Make this a parsed input.
                ['presentValue']]
            )
            _log.debug(f'Response is: {response}')
        except ErrorRejectAbortNack as err:  # TODO: This does not seem to be catching abortPDU errors.
            _log.debug(f'Error reading property {err}')
            response = err
        if isinstance(response, AnyAtomic):  # TODO: The response probably needs to be parsed. See example code.
            response = response.get_value()
            # _log.debug(f'Response from read_property_multiple: {response}')
        return response

    async def write_property(self, device_address: str, object_identifier: str, property_identifier: str, value: any,
                    priority: int, property_array_index: int | None = None):
        value = Null(()) if value is None else value
        # TODO: Is additional casting required?
        try:
            return await self.app.write_property(
                Address(device_address),
                ObjectIdentifier(object_identifier),
                property_identifier,
                value,
                int(property_array_index) if property_array_index is not None else None,
                int(priority)
            )
        except ErrorRejectAbortNack as e:
            print(str(e))

    async def write_property_multiple(self, device_address: str, write_specifications: list):
        # TODO Implement write_property_multiple.
        return []

    async def time_synchronization(self, device_address: str, date_time: datetime = None):
        date_time = date_time if date_time else datetime.now()
        time_synchronization_request = TimeSynchronizationRequest(
            destination=Address(device_address),
            time=DateTime(date=Date(date_time.date()), time=Time(date_time.time()))
        )
        response = await self.app.request(time_synchronization_request)
        if isinstance(response, ErrorRejectAbortNack):
            _log.warning(f'Error calling Time Synchronization Service: {response}')


    async def confirmed_private_transfer(self, address: Address, vendor_id: int, service_number: int,
                                         service_parameters: TagList = None) -> any:
        # TODO: Probably need one or more try blocks.
        # TODO: service_parameters probably needs to already be formatted, but how?
        cpt_request = ConfirmedPrivateTransferRequest(destination=address,
                                                      vendorID=vendor_id,
                                                      serviceNumber=service_number)
        if service_parameters:
            cpt_request.serviceParameters = service_parameters
        response = await self.app.request(cpt_request)
        if isinstance(response, ConfirmedPrivateTransferError):
            _log.warning(f'Error calling Confirmed Private Transfer Service: {response}')
        elif isinstance(response, ConfirmedPrivateTransferACK):
            return response
        else:
            _log.warning(f'Some other Error: {response}')  # TODO: Improve error handling.

    async def send_object_user_lock_time(self, address: Address, device_id: str, object_id: str,
                                         lock_interval: int):
        # TODO: Move this and ObjectUserLockTime to a subclass.
        if lock_interval < 0:
            lock_interval_code = 0xFF
            lock_interval = 0
        elif lock_interval <= 60:
            lock_interval_code = 0
            lock_interval = floor(lock_interval)
        elif lock_interval <= 3600:
            lock_interval_code = 1
            lock_interval = floor(lock_interval / 60)
        elif lock_interval <= 86400:
            lock_interval_code = 2
            lock_interval = floor(lock_interval / 3600)
        elif lock_interval <= 22032000:
            lock_interval_code = 3
            lock_interval = floor(lock_interval / 86400)
        else:
            lock_interval_code = 0xFF
            lock_interval = 0
        response = await self.confirmed_private_transfer(address=Address(address), vendor_id=213, service_number=28,
                                                         service_parameters=TagList([
                                                             OpeningTag(2),
                                                             ObjectIdentifier(device_id, _context=0).encode(),
                                                             ObjectIdentifier(object_id, _context=0).encode(),
                                                             ObjectUserLockTime(lock_interval_code, lock_interval),
                                                             ClosingTag(2)
                                                            ])
                                                         )
        return response  # TODO: Improve error handling.
    
    async def scan_subnet(self,
                          network_str: str,
                          whois_timeout: float = 3.0,
                          port: int = 47808,
                          low_id: int = 0,
                          high_id: int = 4194303,
                          enable_brute_force: bool = True,
                          semaphore_limit: int = 20,
                          max_duration: float = 280.0) -> list:
        """
        Smart subnet scan with global cache-informed scanning and router discovery:
          1. Router discovery (Who-Is-Router-To-Network)
          2. First scan ALL cached device addresses globally (comprehensive discovery)
          3. Directed broadcast Who-Is (subnet broadcast)
          4. Limited broadcast Who-Is (255.255.255.255)
          5. Brute force unicast sweep of remaining addresses (if enabled and needed)

        Note: Step 2 now scans ALL cached devices from ANY network to build comprehensive
        network topology knowledge over time. Devices found on 130.20.24.0/24 will be
        checked when scanning 10.71.19.0/24, enabling cross-network discovery.

        Parameters (removed force_fresh_scan as scan is always real):
          network_str        CIDR (e.g. 192.168.1.0/24)
          whois_timeout      Seconds to wait per broadcast (wait_for timeout)
          port               UDP BACnet port to target (default 47808)
          low_id / high_id   Device instance range filter (default 0-4194303)
          enable_brute_force Whether to fall back to per-host unicast if broadcasts find nothing
          semaphore_limit    Concurrency for brute force sweep (default 20)
          max_duration       Safety cap (seconds) for brute force phase (default 280)
        Returns: list[device_dict]
        """

        start_time = time.time()

        try:
            net = ipaddress.IPv4Network(network_str, strict=False)
        except ValueError as e:
            _log.error(f"[scan_subnet] Invalid network string '{network_str}': {e}")
            return []

        discovered: list[dict] = []
        seen_keys: set = set()
        scanned_ips: set = set()    # Track which IPs we've already scanned
        router_info = []    # Track discovered routers

        def add_devices(devs: list[dict] | None):
            if not devs:
                return
            for d in devs:
                key = (d.get("pduSource"), tuple(d.get("deviceIdentifier", [])))
                if key not in seen_keys:
                    discovered.append(d)
                    seen_keys.add(key)
                    # Track the IP as scanned
                    pdu_source = d.get('pduSource', '')
                    if ':' in pdu_source:
                        ip_str = pdu_source.split(':')[0]
                        try:
                            ip_obj = ipaddress.IPv4Address(ip_str)
                            if ip_obj in net:
                                scanned_ips.add(ip_obj)
                        except ValueError:
                            pass

        # 1. Router discovery - Who-Is-Router-To-Network
        _log.debug(f"[scan_subnet] Starting router discovery for network {network_str}")
        try:
            if hasattr(self.app, 'nse'):
                router_response = await asyncio.wait_for(self.app.nse.who_is_router_to_network(),
                                                         timeout=whois_timeout)

                if router_response:
                    _log.info(f"[scan_subnet] Found {len(router_response)} router responses")
                    for adapter, i_am_router_to_network in router_response:
                        router_address = str(i_am_router_to_network.pduSource)
                        networks = [str(net)
                                    for net in i_am_router_to_network.iartnNetworkList] if hasattr(
                                        i_am_router_to_network, 'iartnNetworkList') else []

                        router_entry = {
                            'router_address': router_address,
                            'networks': networks,
                            'adapter': str(adapter) if adapter else None
                        }
                        router_info.append(router_entry)

                        _log.debug(
                            f"[scan_subnet] Router at {router_address} serves networks: {networks}"
                        )

                        # Try to extract IP from router address and scan it for devices
                        try:
                            if ':' in router_address:
                                router_ip = router_address.split(':')[0]
                            else:
                                router_ip = router_address

                            # Check if router IP is in our target network
                            router_ip_obj = ipaddress.IPv4Address(router_ip)
                            if router_ip_obj in net:
                                # Scan the router itself for BACnet devices
                                dest = f"{router_ip}:{port}"
                                resp = await asyncio.wait_for(self.who_is(low_id, high_id, dest),
                                                              timeout=whois_timeout)
                                if resp:
                                    _log.debug(f"[scan_subnet] Found devices on router {dest}")
                                    add_devices(resp)
                        except (ValueError, asyncio.TimeoutError) as e:
                            _log.debug(
                                f"[scan_subnet] Could not scan router {router_address}: {e}")
                else:
                    _log.debug("[scan_subnet] No routers responded to Who-Is-Router-To-Network")

        except (AttributeError, asyncio.TimeoutError) as e:
            _log.debug(f"[scan_subnet] Router discovery failed or timed out: {e}")
        except Exception as e:
            _log.warning(f"[scan_subnet] Router discovery error: {e}")

        # 2. Global cache-informed scanning - scan ALL known device IPs first (from any network)
        cached_devices = self.load_cached_devices(None)    # Get ALL cached devices globally
        if cached_devices:
            _log.info(
                f"[scan_subnet] Found {len(cached_devices)} global cached devices, scanning them first for comprehensive discovery"
            )

            # Extract unique IP addresses from ALL cached devices (global discovery approach)
            cached_ips = set()
            for device in cached_devices:
                pdu_source = device.get('pduSource', '')
                if ':' in pdu_source:
                    ip_str = pdu_source.split(':')[0]
                    try:
                        ip_obj = ipaddress.IPv4Address(ip_str)
                        # Include ALL cached IPs regardless of network for global discovery
                        cached_ips.add(ip_obj)
                    except ValueError:
                        continue

            # Scan cached IPs with higher concurrency since they're likely to respond
            if cached_ips:
                _log.debug(
                    f"[scan_subnet] Scanning {len(cached_ips)} global cached device IPs for comprehensive discovery"
                )
                sem_cached = asyncio.Semaphore(min(len(cached_ips),
                                                   50))    # Higher concurrency for cached

                async def probe_cached(ip_obj):
                    async with sem_cached:
                        dest = f"{ip_obj}:{port}"
                        try:
                            resp = await asyncio.wait_for(self.who_is(low_id, high_id, dest),
                                                          timeout=whois_timeout)
                            if resp:
                                _log.debug(f"[scan_subnet] Cached device verified at {dest}")
                                add_devices(resp)
                        except Exception:
                            pass    # Cache miss is fine, device may have moved

                cached_tasks = [asyncio.create_task(probe_cached(ip)) for ip in cached_ips]
                if cached_tasks:
                    await asyncio.gather(*cached_tasks, return_exceptions=True)

                _log.info(
                    f"[scan_subnet] Global cached scan complete: {len(discovered)} devices verified from comprehensive discovery"
                )

        # 3. Directed broadcast
        directed_broadcast = f"{net.broadcast_address}:{port}"
        _log.debug(f"[scan_subnet] Directed broadcast Who-Is -> {directed_broadcast}")
        try:
            resp = await asyncio.wait_for(self.who_is(low_id, high_id, directed_broadcast),
                                          timeout=whois_timeout)
            add_devices(resp)
        except asyncio.TimeoutError:
            _log.debug("[scan_subnet] Directed broadcast timeout (continuing)")
        except Exception as e:
            _log.debug(f"[scan_subnet] Directed broadcast error: {e}")

        # 4. Limited broadcast if we haven't found many devices yet
        if len(discovered) < 5:    # Arbitrary threshold - adjust as needed
            limited_broadcast = f"255.255.255.255:{port}"
            _log.debug(f"[scan_subnet] Limited broadcast Who-Is -> {limited_broadcast}")
            try:
                resp = await asyncio.wait_for(self.who_is(low_id, high_id, limited_broadcast),
                                              timeout=whois_timeout)
                add_devices(resp)
            except asyncio.TimeoutError:
                _log.debug("[scan_subnet] Limited broadcast timeout (continuing)")
            except Exception as e:
                _log.debug(f"[scan_subnet] Limited broadcast error: {e}")

        # 5. Brute force unicast sweep of remaining addresses (skip already scanned IPs)
        if enable_brute_force:
            remaining_hosts = [ip for ip in net.hosts() if ip not in scanned_ips]
            host_count = len(remaining_hosts)

            if host_count > 0:
                if host_count > 1024:
                    _log.warning(
                        f"[scan_subnet] Large network sweep: {host_count} remaining hosts")

                _log.debug(
                    f"[scan_subnet] Starting unicast sweep over {host_count} remaining hosts, port={port}, concurrency={semaphore_limit}"
                )
                sem = asyncio.Semaphore(semaphore_limit)

                async def probe(ip_obj):
                    async with sem:
                        if time.time() - start_time > max_duration:
                            return
                        dest = f"{ip_obj}:{port}"
                        try:
                            resp = await self.who_is(low_id, high_id, dest)
                            if resp:
                                _log.debug(
                                    f"[scan_subnet] Unicast hit {dest} -> {len(resp)} device(s)")
                                add_devices(resp)
                        except Exception:
                            pass    # per-host errors are non-fatal

                tasks = []
                for host_ip in remaining_hosts:
                    if time.time() - start_time > max_duration:
                        _log.warning("[scan_subnet] Time limit reached; stopping sweep early")
                        break
                    tasks.append(asyncio.create_task(probe(host_ip)))

                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
            else:
                _log.debug("[scan_subnet] No remaining hosts to scan after cache verification")

        # Save all discovered devices to cache with router information
        for device in discovered:
            # Add router information to device metadata if available
            if router_info:
                device['_router_info'] = router_info
            self.save_discovered_device(device, network_str, "scan")

        elapsed = time.time() - start_time
        _log.info(
            f"[scan_subnet] Complete devices_found={len(discovered)} routers_found={len(router_info)} elapsed={elapsed:.2f}s"
        )

        # Log router summary
        if router_info:
            _log.info(f"[scan_subnet] Router summary:")
            for router in router_info:
                _log.info(f"  Router {router['router_address']} -> Networks: {router['networks']}")

        return discovered

    async def who_is(self, device_instance_low: int, device_instance_high: int, dest: str):
        destination_addr = dest if isinstance(dest, Address) else Address(dest)
        _log.debug(
            f"Sending Who-Is to {destination_addr} (low_id: {device_instance_low}, high_id: {device_instance_high})"
        )

        try:
            # Perform WHO-IS discovery (note: bacpypes3 who_is doesn't accept apdu_timeout parameter)
            i_am_responses = await self.app.who_is(device_instance_low, device_instance_high,
                                                   destination_addr)
            _log.debug(f"Received {len(i_am_responses)} I-Am response(s) from {destination_addr}")

            devices_found = []
            if i_am_responses:
                for i_am_pdu in i_am_responses:
                    # Convert deviceIdentifier to consistent string format
                    device_identifier = i_am_pdu.iAmDeviceIdentifier

                    # Handle both numeric [8, 506892] and string ['device', 506892] formats
                    if isinstance(device_identifier,
                                  (list, tuple)) and len(device_identifier) == 2:
                        obj_type, instance = device_identifier
                        if isinstance(obj_type, int):
                            # Convert numeric object type to string using ObjectType enum
                            try:
                                obj_type_name = ObjectType(obj_type).name
                                device_identifier = [obj_type_name, instance]
                            except (ValueError, AttributeError):
                                # If conversion fails, use string representation
                                device_identifier = [str(obj_type), instance]
                        # If already string format, keep as is

                    device_info = {
                        "pduSource": str(i_am_pdu.pduSource),
                        "deviceIdentifier": device_identifier,
                        "maxAPDULengthAccepted": i_am_pdu.maxAPDULengthAccepted,
                        "segmentationSupported": str(i_am_pdu.segmentationSupported),
                        "vendorID": i_am_pdu.vendorID,
                    }
                    devices_found.append(device_info)
            return devices_found
        except asyncio.TimeoutError:
            _log.warning(f"Who-Is timeout for {destination_addr}")
            return []
        except ErrorRejectAbortNack as e_bac:
            _log.warning(f"BACnet error during Who-Is: {e_bac}")
            return []
        except Exception as e_gen:
            _log.error(f"General error during Who-Is: {e_gen}")
            return []

    def save_discovered_device(self,
                               device_info: dict,
                               network_str: str,
                               scan_method: str = "unknown"):
        """Save a discovered device to CSV cache and RDF graph."""
        try:
            device_instance = device_info.get('deviceIdentifier', [None, None])[1]
            device_address = device_info.get('pduSource', '').split(':')[0]

            if not device_instance or not device_address:
                return

            # Set up cache file path (create directory if needed)
            from pathlib import Path
            cache_dir = Path.home() / '.bacnet_scan_tool'
            cache_dir.mkdir(exist_ok=True)
            device_cache_file = cache_dir / 'discovered_devices.csv'

            # Create CSV if it doesn't exist
            if not device_cache_file.exists():
                with open(device_cache_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        'device_instance', 'device_address', 'vendor_id', 'first_discovered',
                        'last_seen', 'scan_count', 'networks_found_on'
                    ])

            # Read existing data
            existing = {}
            with open(device_cache_file, 'r', newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    existing[(row['device_instance'], row['device_address'])] = row

            # Update or create record
            key = (str(device_instance), device_address)
            now = datetime.now().isoformat()

            if key in existing:
                # Update existing
                existing[key]['last_seen'] = now
                existing[key]['scan_count'] = str(int(existing[key]['scan_count']) + 1)
                networks = existing[key]['networks_found_on'].split(
                    ';') if existing[key]['networks_found_on'] else []
                if network_str not in networks:
                    networks.append(network_str)
                existing[key]['networks_found_on'] = ';'.join(networks)
            else:
                # New device
                existing[key] = {
                    'device_instance': str(device_instance),
                    'device_address': device_address,
                    'vendor_id': str(device_info.get('vendorID', '')),
                    'first_discovered': now,
                    'last_seen': now,
                    'scan_count': '1',
                    'networks_found_on': network_str
                }

            # Write back CSV
            with open(device_cache_file, 'w', newline='') as f:
                fieldnames = [
                    'device_instance', 'device_address', 'vendor_id', 'first_discovered',
                    'last_seen', 'scan_count', 'networks_found_on'
                ]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(existing.values())

            # Also save JSON copy
            device_json_file = cache_dir / 'discovered_devices.json'
            with open(device_json_file, 'w') as f:
                json.dump(list(existing.values()), f, indent=2)

            # Save to RDF graph (Turtle format)
            try:
                rdf_path = cache_dir / 'discovered_devices.ttl'
                from rdflib import Graph
                from bacpypes3.rdf.core import BACnetGraph
                from bacpypes3.pdu import Address
                from bacpypes3.primitivedata import ObjectIdentifier

                rdf_graph = Graph()
                bacnet_graph = BACnetGraph(rdf_graph)

                device_identifier = device_info.get("deviceIdentifier", [None, None])
                if device_identifier and len(device_identifier) == 2:
                    object_type, instance = device_identifier

                    # Ensure we have valid values
                    if object_type is None or instance is None:
                        _log.warning(f"Invalid device identifier: {device_identifier}")
                        return

                    pdu_source = device_info.get("pduSource", "")
                    if not pdu_source:
                        _log.warning("No pduSource found in device_info")
                        return

                    # Parse IP and port
                    if ":" in pdu_source:
                        ip_str, port = pdu_source.split(":", 1)
                    else:
                        ip_str, port = pdu_source, "47808"

                    # Create ObjectIdentifier with proper format (use comma separator)
                    try:
                        object_identifier = ObjectIdentifier(f"{object_type},{instance}")
                    except Exception as oid_e:
                        _log.error(
                            f"Error creating ObjectIdentifier with '{object_type},{instance}': {oid_e}"
                        )
                        # Try with colon separator as backup
                        try:
                            object_identifier = ObjectIdentifier(f"{object_type}:{instance}")
                        except Exception as oid_e2:
                            _log.error(
                                f"Error creating ObjectIdentifier with '{object_type}:{instance}': {oid_e2}"
                            )
                            return

                    # Create Address - prefer simple IP address for most cases
                    try:
                        network_number = device_info.get("networkNumber", 0)
                        mac_address = device_info.get("macAddress", b"")

                        # Use network address only if we have a valid MAC address and network number
                        if (mac_address and isinstance(mac_address,
                                                       (bytes, bytearray)) and len(mac_address) > 0
                                and network_number is not None and network_number > 0):
                            address = Address(addrNet=int(network_number), addrAddr=mac_address)
                        else:
                            # Use simple IP address for local network devices
                            address = Address(ip_str)

                    except Exception as addr_e:
                        _log.error(f"Error creating Address: {addr_e}")
                        # Fallback to simple IP address
                        try:
                            address = Address(ip_str)
                        except Exception as addr_e2:
                            _log.error(
                                f"Error creating fallback Address with IP '{ip_str}': {addr_e2}")
                            return

                    # Create device in RDF graph
                    try:
                        bacnet_graph.create_device(address, object_identifier)
                        rdf_graph.serialize(destination=str(rdf_path), format="turtle")
                        _log.info(f"Saved device {instance} at {ip_str} to RDF: {rdf_path}")
                    except Exception as create_e:
                        _log.error(f"Error creating device in RDF graph: {create_e}")

                else:
                    _log.warning(f"Invalid deviceIdentifier format: {device_identifier}")

            except Exception as rdf_e:
                _log.error(f"Error saving device to RDF: {rdf_e}")
                import traceback
                _log.error(traceback.format_exc())

                _log.info(
                    f"Saved device {device_instance} at {device_address} to {device_cache_file} and JSON"
                )

        except Exception as e:
            _log.error(f"Error saving device: {e}")

    def load_cached_devices(self, network_str: str = None) -> list:
        """Load cached devices from CSV file.

        Args:
            network_str: Optional network filter (e.g., "192.168.1.0/24")
                        If provided, only returns devices found on that network
                        If None, returns ALL cached devices globally (for comprehensive discovery)

        Returns:
            list: Devices in same format as scan_subnet returns
        """
        try:
            from pathlib import Path
            cache_dir = Path.home() / '.bacnet_scan_tool'
            device_cache_file = cache_dir / 'discovered_devices.csv'

            if not device_cache_file.exists():
                _log.debug("No device cache file found")
                return []

            devices = []
            with open(device_cache_file, 'r', newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Filter by network if specified
                    if network_str:
                        networks = row.get('networks_found_on',
                                           '').split(';') if row.get('networks_found_on') else []
                        if network_str not in networks:
                            continue

                    # Convert back to scan_subnet format
                    device = {
                        'pduSource':
                        f"{row['device_address']}:47808",
                        'deviceIdentifier': ['device', int(row['device_instance'])],
                        'vendorID':
                        int(row['vendor_id'])
                        if row['vendor_id'] and row['vendor_id'].isdigit() else None,
                        'vendorName':
                        '',    # Could be looked up from vendor_id
                        'maxAPDULengthAccepted':
                        None,    # Not stored in cache
                        'segmentationSupported':
                        None,    # Not stored in cache
                        '_cached':
                        True,    # Mark as from cache
                        '_cache_info': {
                            'first_discovered':
                            row['first_discovered'],
                            'last_seen':
                            row['last_seen'],
                            'scan_count':
                            int(row['scan_count']) if row['scan_count'].isdigit() else 0,
                            'networks':
                            row.get('networks_found_on', '').split(';')
                            if row.get('networks_found_on') else []
                        }
                    }
                    devices.append(device)

            _log.info(f"Loaded {len(devices)} cached devices" +
                      (f" for network {network_str}" if network_str else ""))
            return devices

        except Exception as e:
            _log.error(f"Error loading cached devices: {e}")
            return []

    async def read_object_list_names_paginated(self,
                                               device_address: str,
                                               device_object_identifier: str,
                                               page: int = 1,
                                               page_size: int = 100,
                                               force_fresh_read: bool = False,
                                               object_list_cache: dict = None,
                                               cache_timeout: int = 300) -> dict:
        """
        Reads object properties with CSV caching support.

        Parameters:
            force_fresh_read: If True, skip cache and read fresh from device
        """
        _log.info(
            f"Starting read_object_list_names_paginated for device {device_address}, page {page}, page_size {page_size}, force_fresh_read={force_fresh_read}"
        )

        # Validate pagination parameters
        if page < 1:
            return {"status": "error", "error": "Page number must be >= 1"}
        if page_size < 1 or page_size > 1000:
            return {"status": "error", "error": "Page size must be between 1 and 1000"}

        # Check cache first (unless force_fresh_read is True)
        if not force_fresh_read:
            cached_result = load_cached_object_properties(device_address, device_object_identifier,
                                                          page, page_size)
            if cached_result:
                _log.info(
                    f"Returning cached object properties for device {device_address}, page {page}")
                return cached_result

        # Cache miss or forced fresh read - get from device
        _log.info(f"Cache miss or fresh read forced - reading from device {device_address}")

        # Step 1: Get object-list from cache or read from device
        object_list = await _get_cached_object_list(self, object_list_cache, cache_timeout,
                                                    device_address, device_object_identifier)

        if object_list is None:
            return {"status": "error", "error": "Failed to read object-list from device"}

        total_objects = len(object_list)
        total_pages = (total_objects + page_size - 1) // page_size

        _log.info(f"Object-list has {total_objects} objects, {total_pages} total pages")

        # Calculate pagination bounds
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size

        # Get the page of objects
        page_objects = object_list[start_idx:end_idx]

        if not page_objects:
            return {"status": "error", "error": "No objects found for this page"}

        # Step 2: Prepare batch read for object-name, units, and present-value of each object
        daopr_list = []

        for objid in page_objects:
            # Always read object-name for all objects
            daopr_list.append(
                DeviceAddressObjectPropertyReference(
                    key=f"{objid}:object-name",
                    device_address=device_address,
                    object_identifier=objid,
                    property_reference=PropertyReference("object-name")))

            # Only read units and present-value for objects that typically have them
            obj_type = str(objid).split(',')[0] if ',' in str(objid) else str(objid)

            # Skip units and present-value for object types that don't typically have them
            skip_types = [
                'device', 'program', 'schedule', 'trend-log', 'file', 'group', 'notification-class'
            ]

            if obj_type not in skip_types:
                # Read units (if applicable)
                daopr_list.append(
                    DeviceAddressObjectPropertyReference(
                        key=f"{objid}:units",
                        device_address=device_address,
                        object_identifier=objid,
                        property_reference=PropertyReference("units")))
                # Read present-value (if applicable)
                daopr_list.append(
                    DeviceAddressObjectPropertyReference(
                        key=f"{objid}:present-value",
                        device_address=device_address,
                        object_identifier=objid,
                        property_reference=PropertyReference("present-value")))

        _log.info(f"Prepared batch read for {len(daopr_list)} objects on page {page}")

        # Step 3: Execute batch read
        raw_results = {}

        def callback(key, value):
            logging.getLogger(__name__).debug(f"BatchRead callback: key={key}, value={value}")
            raw_results[key] = value

        batch = BatchRead(daopr_list)
        try:
            await asyncio.wait_for(batch.run(self.app, callback=callback), timeout=90)
            logging.getLogger(__name__).info(
                f"BatchRead completed successfully with {len(raw_results)} raw results for page {page}"
            )

            # Check if we have any results after the batch read
            if not raw_results:
                logging.getLogger(__name__).warning(
                    "BatchRead completed but no results were received")
                return {"status": "error", "error": "No results received from BACnet device"}

            # Process raw results to organize by object identifier
            results = {}
            objects_to_cache = {}

            for key, value in raw_results.items():
                if ':' in key:
                    obj_id, property_name = key.rsplit(':', 1)
                    if obj_id not in results:
                        results[obj_id] = {}
                    if obj_id not in objects_to_cache:
                        objects_to_cache[obj_id] = {}

                    results[obj_id][property_name] = value
                    objects_to_cache[obj_id][property_name] = value
                else:
                    # Fallback for any keys without property suffix
                    results[key] = value

            # Save to cache
            for obj_id, properties in objects_to_cache.items():
                save_object_properties(device_address, device_object_identifier, obj_id,
                                       properties)

        except asyncio.TimeoutError:
            logging.getLogger(__name__).error(
                f"BatchRead timed out after 90 seconds for page {page}!")
            return {
                "status": "error",
                "error": "Timeout waiting for BACnet device response after 90 seconds"
            }
        except Exception as e:
            logging.getLogger(__name__).exception(f"Exception in BatchRead for page {page}: {e}")
            return {"status": "error", "error": f"BatchRead failed: {str(e)}"}

        # Return paginated response
        return {
            "status": "done",
            "results": results,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_items": total_objects,
                "total_pages": total_pages,
                "has_next": page < total_pages,
                "has_previous": page > 1
            },
            "_from_cache": False
        }

    async def read_device_all(self, device_address: str, device_object_identifier: str) -> dict:
        properties = [
            "object-identifier",
            "object-name",
            "object-type",
            "system-status",
            "vendor-name",
            "vendor-identifier",
            "model-name",
            "firmware-revision",
            "application-software-version",
            "location",
            "description",
            "protocol-version",
            "protocol-revision",
            "protocol-services-supported",
            "protocol-object-types-supported",
            "object-list",
            "structured-object-list",
            "max-apdu-length-accepted",
            "segmentation-supported",
            "max-segments-accepted",
            "vt-classes-supported",
            "active-vt-sessions",
            "local-time",
            "local-date",
            "utc-offset",
            "daylight-savings-status",
            "apdu-segment-timeout",
            "apdu-timeout",
            "number-of-apdu-retries",
            "time-synchronization-recipients",
            "max-master",
            "max-info-frames",
            "device-address-binding",
            "database-revision",
            "configuration-files",
            "last-restore-time",
            "backup-failure-timeout",
            "backup-preparation-time",
            "restore-preparation-time",
            "restore-completion-time",
            "backup-and-restore-state",
            "active-cov-subscriptions",
            "last-restart-reason",
            "time-of-device-restart",
            "restart-notification-recipients",
            "utc-time-synchronization-recipients",
            "time-synchronization-interval",
            "align-intervals",
            "interval-offset",
            "serial-number",
            "property-list",
            "status-flags",
            "event-state",
            "reliability",
            "event-detection-enable",
            "notification-class",
            "event-enable",
            "acked-transitions",
            "notify-type",
            "event-time-stamps",
            "event-message-texts",
            "event-message-texts-config",
            "reliability-evaluation-inhibit",
            "active-cov-multiple-subscriptions",
            "audit-notification-recipient",
            "audit-level",
            "auditable-operations",
            "device-uuid",
            "tags",
            "profile-location",
            "deployed-profile-location",
            "profile-name",
        ]
        device_obj = ObjectIdentifier(device_object_identifier)
        daopr_list = [
            DeviceAddressObjectPropertyReference(key=prop,
                                                 device_address=device_address,
                                                 object_identifier=device_obj,
                                                 property_reference=PropertyReference(prop))
            for prop in properties
        ]
        results = {}

        def callback(key, value):
            logging.getLogger(__name__).debug(f"BatchRead callback: key={key}, value={value}")
            results[key] = value

        batch = BatchRead(daopr_list)
        try:
            await asyncio.wait_for(batch.run(self.app, callback=callback), timeout=30)
        except asyncio.TimeoutError:
            logging.getLogger(__name__).error("BatchRead timed out after 30 seconds!")
            results['error'] = 'Timeout waiting for BACnet device response.'
        except Exception as e:
            logging.getLogger(__name__).exception(f"Exception in BatchRead: {e}")
            results['error'] = str(e)
        return results


class ObjectUserLockTime(Tag):
    def __init__(self, interval_code, interval_value, *args):
        super(ObjectUserLockTime, self).__init__(*args)
        self.interval_code: int = interval_code
        self.interval_value: int = interval_value

    def encode(self) -> PDUData:
        pdu_data = PDUData()
        pdu_data.put(self.interval_code)
        pdu_data.put(self.interval_value)
        return pdu_data


async def run_proxy(local_device_address, **kwargs):
    bp = BACnetProxy(local_device_address, **kwargs)
    await bp.start()


def launch_bacnet(parser: ArgumentParser) -> tuple[ArgumentParser, Type[AsyncioProtocolProxy]]:
    parser.add_argument('--local-device-address', type=str, required=True,
                        help='Address on the local machine of this BACnet Proxy.')
    parser.add_argument('--bacnet-network', type=int, default=0,
                        help='The BACnet port as an offset from 47808.')
    parser.add_argument('--vendor-id', type=int, default=999,
                        help='The BACnet vendor ID to use for the local device of this BACnet Proxy.')
    parser.add_argument('--object-name', type=str, default='VOLTTRON BACnet Proxy',
                        help='The name of the local device for this BACnet Proxy.')
    return parser, run_proxy


if __name__ == '__main__':
    sys.exit(launch(launch_bacnet))
