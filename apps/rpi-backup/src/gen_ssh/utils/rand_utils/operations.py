from __future__ import annotations

from uuid import uuid4

def random_keyname(length: int = 12) -> str:
    """Generate a random keyname from a UUID.
    
    Creates a unique name by generating a UUID, stripping the '-' characters,
    then returning the first n characters of the string, determined by 'length.'
    
    Params:
    -------
    
    * length (int): Number of characters to return. Default is 12. Max is 32.
    """
    if length <= 0 or length > 32:
        raise ValueError(f"Invalid length: {length}. Must be between 1 and 32.")

    _uuid : str = str(uuid4()).replace("-", "")
    return _uuid[:length]
