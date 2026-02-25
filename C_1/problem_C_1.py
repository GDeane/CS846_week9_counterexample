from datetime import datetime, timedelta

def add_days(date_str: str, days: int) -> str:
    """
    Input:  date_str in 'YYYY-MM-DD'
    Output: date_str in 'YYYY-MM-DD' after adding days
    """
    dt = datetime.strptime(date_str, "%Y-%m-%d")  # crashes on invalid dates
    return (dt + timedelta(days=days)).strftime("%Y-%m-%d")
