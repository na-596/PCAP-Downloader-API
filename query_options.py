from datetime import datetime, timedelta


"""Utilities for building common time windows used by the UI.

get_time_window accepts a short option string and returns a (start, end)
tuple formatted as "YYYY/MM/DD HH:MM:SS" which matches the format expected by
other components in the publish package.
"""


def get_time_window(option: str):
    now = datetime.today()
    if option == "last_half_hour":
        start = now - timedelta(minutes=30)
    elif option == "last_hour":
        start = now - timedelta(hours=1)
    elif option == "last_6_hours":
        start = now - timedelta(hours=6)
    elif option == "last_24_hours":
        start = now - timedelta(hours=24)
    elif option == "last_48_hours":
        start = now - timedelta(hours=48)
    elif option == "last_72_hours":
        start = now - timedelta(hours=72)
    elif option == "last_week":
        start = now - timedelta(weeks=1)
    elif option == "last_2_weeks":
        start = now - timedelta(weeks=2)
    elif option == "last_month":
        start = now - timedelta(days=30)
    elif option == "last_2_months":
        start = now - timedelta(days=60)
    elif option == "last_6_months":
        start = now - timedelta(days=180)
    elif option == "last_year":
        start = now - timedelta(days=365)
    elif option == "all_time":
        start = datetime(1970, 1, 1, 0, 0, 0)
    else:
        raise ValueError("Invalid time window option")

    # Format: "YYYY/MM/DD HH:MM:SS" for UI and downstream components that accept seconds
    time_window_start = start.strftime("%Y/%m/%d %H:%M:%S")
    time_window_end = now.strftime("%Y/%m/%d %H:%M:%S")

    return time_window_start, time_window_end
