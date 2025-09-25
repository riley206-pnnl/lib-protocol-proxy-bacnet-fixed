#!/usr/bin/env python3
"""
BACnet Broadcast Workaround - Uses existing app instead of creating new one
"""
import asyncio
import logging
import time
from typing import List, Dict, Any
from bacpypes3.pdu import Address
from bacpypes3.apdu import WhoIsRequest

class BACnetDevice:
    """Represents a discovered BACnet device"""
    def __init__(self, iam_pdu):
        self.device_id = str(iam_pdu.iAmDeviceIdentifier)
        self.device_instance = iam_pdu.iAmDeviceIdentifier[1]
        self.source_address = str(iam_pdu.pduSource)
        self.vendor_id = iam_pdu.vendorID
        self.max_apdu_length = iam_pdu.maxAPDULengthAccepted
        self.segmentation_supported = str(iam_pdu.segmentationSupported)
        self.discovered_at = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'device_id': self.device_id,
            'device_instance': self.device_instance,
            'source_address': self.source_address,
            'vendor_id': self.vendor_id,
            'max_apdu_length': self.max_apdu_length,
            'segmentation_supported': self.segmentation_supported,
            'discovered_at': self.discovered_at
        }
    
    def __str__(self):
        return f"Device {self.device_instance} at {self.source_address} (vendor: {self.vendor_id})"

class ExistingAppBroadcastWorkaround:
    """
    Broadcast workaround that uses an existing BACnet app instead of creating a new one.
    This avoids port conflicts.
    """
    
    def __init__(self, existing_app):
        self.app = existing_app  # Use existing app
        self.discovered_devices = {}
        self.response_lock = asyncio.Lock()
        self.original_indication = None
        self.logger = logging.getLogger(__name__)
        
    async def initialize(self):
        """Initialize the broadcast workaround on existing app"""
        self.logger.info("Initializing broadcast workaround on existing app")
        
        # Install I-Am capture hook on existing app
        self._install_capture_hook()
        
        self.logger.info("Broadcast workaround initialized successfully")
    
    def _install_capture_hook(self):
        """Install I-Am capture on the existing app"""
        # Save original indication handler
        self.original_indication = getattr(self.app, 'indication', None)
        
        async def enhanced_indication_handler(pdu):
            # Capture I-Am responses for broadcast workaround
            if hasattr(pdu, 'iAmDeviceIdentifier'):
                await self._capture_iam_response(pdu)
            
            # Call original handler
            if self.original_indication:
                if asyncio.iscoroutinefunction(self.original_indication):
                    await self.original_indication(pdu)
                else:
                    self.original_indication(pdu)
        
        # Replace indication handler
        setattr(self.app, 'indication', enhanced_indication_handler)
        self.logger.debug("I-Am capture hook installed on existing app")
    
    async def _capture_iam_response(self, pdu):
        """Capture I-Am response"""
        try:
            device_instance = pdu.iAmDeviceIdentifier[1]
            source_address = str(pdu.pduSource)
            
            async with self.response_lock:
                device_key = f"{device_instance}@{source_address}"
                
                if device_key not in self.discovered_devices:
                    device = BACnetDevice(pdu)
                    self.discovered_devices[device_key] = device
                    self.logger.info(f"[WORKAROUND] Captured: {device}")
                    return True
                
            return False
            
        except Exception as e:
            self.logger.error(f"Error capturing I-Am response: {e}")
            return False
    
    async def discover_devices(self, 
                              broadcast_address: str,
                              device_range: tuple = (0, 4194303),
                              timeout: float = 5.0) -> List[BACnetDevice]:
        """
        Discover devices using existing app
        """
        low_id, high_id = device_range
        
        self.logger.info(f"[WORKAROUND] Starting broadcast discovery to {broadcast_address}")
        self.logger.debug(f"[WORKAROUND] Device range: {low_id}-{high_id}, Timeout: {timeout}s")
        
        # Clear previous discoveries
        async with self.response_lock:
            self.discovered_devices.clear()
        
        try:
            # Create and send broadcast Who-Is request
            who_is = WhoIsRequest()
            if low_id is not None:
                who_is.deviceInstanceRangeLowLimit = low_id
            if high_id is not None:
                who_is.deviceInstanceRangeHighLimit = high_id
            
            who_is.pduDestination = Address(broadcast_address)
            
            # Send via existing app
            start_time = time.time()
            self.logger.debug(f"[WORKAROUND] Sending Who-Is via existing app")
            await self.app.request(who_is)
            
            # Wait for I-Am responses
            await asyncio.sleep(timeout)
            
            # Get discovered devices
            async with self.response_lock:
                devices = list(self.discovered_devices.values())
            
            elapsed = time.time() - start_time
            self.logger.info(f"[WORKAROUND] Discovery complete: {len(devices)} devices in {elapsed:.2f}s")
            
            return devices
            
        except Exception as e:
            self.logger.error(f"[WORKAROUND] Error in discovery: {e}")
            import traceback
            self.logger.error(f"[WORKAROUND] Traceback: {traceback.format_exc()}")
            return []
    
    def cleanup(self):
        """Restore original indication handler"""
        if self.original_indication:
            setattr(self.app, 'indication', self.original_indication)
            self.logger.debug("Original indication handler restored")