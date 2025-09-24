from protocol_proxy.protocol.bacnet.logging_utils import _log
from bacpypes3.apdu import AbortPDU, ErrorPDU, ErrorRejectAbortNack, RejectPDU
import time
from datetime import datetime
import csv
import traceback
import json

# Global cache variables
_object_list_cache = {}
_cache_timeout = 300    # 5 minutes


async def _get_cached_object_list(bacnet_instance, object_list_cache, cache_timeout,
                                  device_address: str, device_object_identifier: str):
    """
    Get object-list from cache if available and not expired, otherwise read from device.
    Returns the object-list or None if there was an error.
    """
    cache_key = f"{device_address}:{device_object_identifier}"
    current_time = time.time()

    # Check cache first
    if cache_key in object_list_cache:
        object_list, timestamp = object_list_cache[cache_key]
        if current_time - timestamp < cache_timeout:
            _log.debug(f"Using cached object-list for {cache_key}")
            return object_list

    # Cache miss or expired - read from device
    try:
        _log.info(
            f"Reading object-list from device {device_address} with device_object_identifier='{device_object_identifier}'"
        )
        object_list = await bacnet_instance.read_property(device_address, device_object_identifier,
                                                          "object-list")

        # Add detailed logging of what we got back
        _log.info(
            f"Raw object-list response from {device_address}: type={type(object_list)}, value={object_list}"
        )

        # Check for BACnet error responses
        if isinstance(object_list, (AbortPDU, ErrorPDU, RejectPDU, ErrorRejectAbortNack)):
            _log.error(
                f"BACnet error reading object-list from {device_address}: {type(object_list).__name__} - {object_list}"
            )

            # If it's an ErrorPDU, log more details
            if isinstance(object_list, ErrorPDU):
                error_class = getattr(object_list, 'errorClass', 'Unknown')
                error_code = getattr(object_list, 'errorCode', 'Unknown')
                _log.error(f"ErrorPDU details: errorClass={error_class}, errorCode={error_code}")

            return None

        # Ensure it's actually a list/iterable
        if object_list and hasattr(object_list,
                                   '__iter__') and not isinstance(object_list, (str, bytes)):
            object_list_cache[cache_key] = (object_list, current_time)
            _log.info(
                f"Successfully cached object-list for {cache_key} with {len(object_list)} objects")
            return object_list
        else:
            _log.error(
                f"Invalid object-list response from {device_address}: type={type(object_list)}, value={object_list}"
            )
            return None

    except Exception as e:
        _log.error(f"Exception reading object-list from {device_address}: {e}")
        _log.error(f"Exception traceback: {traceback.format_exc()}")
        return None


def _clear_cache_for_device(object_list_cache,
                            device_address: str,
                            device_object_identifier: str = None):
    """Clear cache for a specific device or all devices."""
    if device_object_identifier:
        cache_key = f"{device_address}:{device_object_identifier}"
        if cache_key in object_list_cache:
            del object_list_cache[cache_key]
            _log.debug(f"Cleared cache for {cache_key}")
    else:
        # Clear all entries for this device address
        keys_to_remove = [
            key for key in object_list_cache.keys() if key.startswith(f"{device_address}:")
        ]
        for key in keys_to_remove:
            del object_list_cache[key]
        _log.debug(f"Cleared cache for all objects at {device_address}")


def _get_cache_stats(object_list_cache, cache_timeout):
    """Get cache statistics for debugging."""
    current_time = time.time()
    stats = {"total_entries": len(object_list_cache), "entries": []}

    for cache_key, (object_list, timestamp) in object_list_cache.items():
        age = current_time - timestamp
        stats["entries"].append({
            "device": cache_key,
            "object_count": len(object_list) if object_list else 0,
            "age_seconds": age,
            "expired": age > cache_timeout
        })

    return stats


def save_object_properties(device_address: str, device_object_identifier: str, object_id: str,
                           properties: dict):
    """Save object properties to CSV cache."""
    try:
        from pathlib import Path
        cache_dir = Path.home() / '.bacnet_scan_tool'
        cache_dir.mkdir(exist_ok=True)
        object_cache_file = cache_dir / 'object_properties.csv'

        # Create CSV if it doesn't exist
        if not object_cache_file.exists():
            with open(object_cache_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'device_address', 'device_object_identifier', 'object_id', 'object_name',
                    'units', 'present_value', 'object_type', 'first_discovered', 'last_updated',
                    'read_count'
                ])

        # Read existing data
        existing = {}
        with open(object_cache_file, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                key = (row['device_address'], row['device_object_identifier'], row['object_id'])
                existing[key] = row

        # Helper function to safely convert property values
        def safe_property_value(value):
            if value is None:
                return ""
            # Check if it's an ErrorType object
            if hasattr(value, '__class__') and 'ErrorType' in str(value.__class__):
                return ""    # Skip error values
            return str(value)

        # Update or create record
        key = (device_address, device_object_identifier, object_id)
        now = datetime.now().isoformat()

        if key in existing:
            # Update existing
            existing[key]['last_updated'] = now
            existing[key]['read_count'] = str(int(existing[key]['read_count']) + 1)
            # Update properties if they exist and aren't errors
            if 'object-name' in properties:
                existing[key]['object_name'] = safe_property_value(properties['object-name'])
            if 'units' in properties:
                existing[key]['units'] = safe_property_value(properties['units'])
            if 'present-value' in properties:
                existing[key]['present_value'] = safe_property_value(properties['present-value'])
        else:
            # New object
            existing[key] = {
                'device_address': device_address,
                'device_object_identifier': device_object_identifier,
                'object_id': object_id,
                'object_name': safe_property_value(properties.get('object-name', '')),
                'units': safe_property_value(properties.get('units', '')),
                'present_value': safe_property_value(properties.get('present-value', '')),
                'object_type': str(properties.get('object-type', '')),
                'first_discovered': now,
                'last_updated': now,
                'read_count': '1'
            }

        # Write back CSV
        with open(object_cache_file, 'w', newline='') as f:
            fieldnames = [
                'device_address', 'device_object_identifier', 'object_id', 'object_name', 'units',
                'present_value', 'object_type', 'first_discovered', 'last_updated', 'read_count'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(existing.values())

        # Also save JSON copy
        object_json_file = cache_dir / 'object_properties.json'
        with open(object_json_file, 'w') as f:
            json.dump(list(existing.values()), f, indent=2)

        _log.debug(
            f"Saved object {object_id} properties for device {device_address} to CSV and JSON")

    except Exception as e:
        _log.error(f"Error saving object properties: {e}")


def load_cached_object_properties(device_address: str,
                                  device_object_identifier: str,
                                  page: int = 1,
                                  page_size: int = 100) -> dict:
    """Load cached object properties from CSV file with pagination."""
    try:
        from pathlib import Path
        cache_dir = Path.home() / '.bacnet_scan_tool'
        object_cache_file = cache_dir / 'object_properties.csv'

        if not object_cache_file.exists():
            _log.debug("No object properties cache file found")
            return None

        # Read all objects for this device
        device_objects = []
        with open(object_cache_file, 'r', newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if (row['device_address'] == device_address
                        and row['device_object_identifier'] == device_object_identifier):
                    device_objects.append(row)

        if not device_objects:
            _log.debug(f"No cached objects found for device {device_address}")
            return None

        # Calculate pagination based on cached objects
        total_cached_objects = len(device_objects)
        total_cached_pages = (total_cached_objects + page_size - 1) // page_size

        # Check if the requested page exists in our cache
        if page > total_cached_pages:
            _log.debug(
                f"Requested page {page} is beyond cached data (cached pages: {total_cached_pages}), falling back to fresh read"
            )
            return None    # Fall back to fresh read

        # We have this page in cache, return it
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        page_objects = device_objects[start_idx:end_idx]

        # Convert to expected format
        results = {}
        for obj in page_objects:
            obj_id = obj['object_id']
            results[obj_id] = {
                'object-name': obj['object_name'] if obj['object_name'] else None,
                'units': obj['units'] if obj['units'] else None,
                'present-value': obj['present_value'] if obj['present_value'] else None,
                '_cached': True,
                '_cache_info': {
                    'first_discovered': obj['first_discovered'],
                    'last_updated': obj['last_updated'],
                    'read_count': int(obj['read_count']) if obj['read_count'].isdigit() else 0
                }
            }

        _log.info(f"Loaded {len(results)} cached objects for device {device_address}, page {page}")

        return {
            "status": "done",
            "results": results,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_items": total_cached_objects,
                "total_pages": total_cached_pages,
                "has_next": page < total_cached_pages,
                "has_previous": page > 1
            },
            "_from_cache": True
        }

    except Exception as e:
        _log.error(f"Error loading cached object properties: {e}")
        return None
