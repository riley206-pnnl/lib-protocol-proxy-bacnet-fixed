from bacpypes3.apdu import AbortPDU, ErrorPDU, ErrorRejectAbortNack, RejectPDU


def make_jsonable(val):
    """Unified function to convert BACnet objects to JSON-serializable format."""
    # Handle basic JSON-serializable types
    if isinstance(val, (str, int, float, bool)):
        return val

    if val is None:
        return None

    # Handle collections
    if isinstance(val, (list, tuple, set)):
        return [make_jsonable(v) for v in val]

    if isinstance(val, dict):
        return {str(k): make_jsonable(v) for k, v in val.items()}

    # Handle binary data
    if isinstance(val, (bytes, bytearray)):
        return val.hex()

    # Handle IP addresses
    if hasattr(val, '__class__'):
        class_name = val.__class__.__name__
        if 'IPv4Address' in class_name or 'IPv6Address' in class_name:
            return str(val)

    # Handle BACnet EngineeringUnits (both objects and integers)
    if hasattr(val, '__class__') and 'EngineeringUnits' in str(val.__class__):
        unit_str = str(val)
        if unit_str.startswith('EngineeringUnits(') and unit_str.endswith(')'):
            return unit_str[17:-1]    # Remove "EngineeringUnits(" and ")"
        return unit_str

    # Handle Python enums
    if hasattr(val, 'name') and hasattr(val, 'value'):
        return str(val.name)
    if hasattr(val, 'name') and not hasattr(val, 'value'):
        return str(val.name)

    # Handle objects with as_tuple method (BACnet objects)
    if hasattr(val, 'as_tuple'):
        return str(val)

    # Handle error objects
    if hasattr(val, '__class__') and 'Error' in val.__class__.__name__:
        return None    # or str(val) if you want error details

    # Handle objects with __dict__ (convert to dict)
    if hasattr(val, '__dict__') and not isinstance(val, type):
        return {str(k): make_jsonable(v) for k, v in val.__dict__.items()}

    # Handle BACnet EngineeringUnits string representations
    if hasattr(val, '__str__'):
        val_str = str(val)
        if 'ErrorType' in val_str or 'Error' in type(val).__name__:
            return None
        if 'EngineeringUnits:' in val_str or 'EngineeringUnits(' in val_str:
            import re
            match = re.search(r'EngineeringUnits(?:\(|:)\s*([^>)]+)', val_str)
            if match:
                return match.group(1).strip()
        return val_str

    # Final fallback
    return str(val)


def _handle_bacnet_response(result):
    """Helper method to handle BACnet responses and convert errors to JSON-serializable format."""
    if isinstance(result, AbortPDU):
        return {
            "error":
            "AbortPDU",
            "reason":
            str(result.apduAbortRejectReason)
            if hasattr(result, 'apduAbortRejectReason') else "Unknown abort reason",
            "details":
            str(result)
        }
    elif isinstance(result, ErrorPDU):
        return {
            "error": "ErrorPDU",
            "error_class": str(result.errorClass) if hasattr(result, 'errorClass') else "Unknown",
            "error_code": str(result.errorCode) if hasattr(result, 'errorCode') else "Unknown",
            "details": str(result)
        }
    elif isinstance(result, RejectPDU):
        return {
            "error":
            "RejectPDU",
            "reason":
            str(result.apduAbortRejectReason)
            if hasattr(result, 'apduAbortRejectReason') else "Unknown reject reason",
            "details":
            str(result)
        }
    elif isinstance(result, ErrorRejectAbortNack):
        return {"error": "ErrorRejectAbortNack", "details": str(result)}
    else:
        return result
