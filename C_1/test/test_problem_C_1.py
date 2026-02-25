from date_utils import add_days

def test_valid_date():
    assert add_days("2026-02-24", 1) == "2026-02-25"

def test_invalid_date_day_out_of_range():
    # Feb 30 is invalid
    add_days("2026-02-30", 1)

def test_invalid_format():
    add_days("02/24/2026", 1)

if __name__ == "__main__":
    test_valid_date()
    try:
        test_invalid_date_day_out_of_range()
    except Exception as e:
        print("Caught:", type(e).__name__, e)

    try:
        test_invalid_format()
    except Exception as e:
        print("Caught:", type(e).__name__, e)
