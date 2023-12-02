import pendulum
from typing import Union


def get_ts_today(
    as_str: bool = True, fmt: str = "%Y-%m-%d"
) -> Union[str, pendulum.DateTime]:
    """Get a timestamp.

    Optionally, return as a formatted string (default behavior).
    """
    ts = pendulum.now()

    if as_str:
        formatted_ts = ts.strftime(fmt)

        return formatted_ts
    else:
        return ts
