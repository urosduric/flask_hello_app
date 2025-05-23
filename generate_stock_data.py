import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from pandas.tseries.holiday import USFederalHolidayCalendar

# Set random seed for reproducibility
np.random.seed(42)

# Generate dates for the last 10 years
end_date = datetime.now()
start_date = end_date - timedelta(days=365*10)

# Create a calendar with US Federal Holidays
cal = USFederalHolidayCalendar()
holidays = cal.holidays(start=start_date, end=end_date).to_pydatetime().tolist()

# Generate business days
dates = pd.date_range(start=start_date, end=end_date, freq='B')
# Remove holidays
dates = dates[~dates.isin(holidays)]

# Generate daily returns with some realistic properties
# Mean daily return of 0.0003 (roughly 7.5% annual return)
# Standard deviation of 0.012 (roughly 19% annualized volatility)
daily_returns = np.random.normal(loc=0.0003, scale=0.012, size=len(dates))

# Add some fat tails and volatility clustering
# Occasionally add some larger moves
for i in range(len(daily_returns)):
    if np.random.random() < 0.01:  # 1% chance of a large move
        daily_returns[i] *= 3

# Create DataFrame
df = pd.DataFrame({
    'date': dates,
    'daily_return': daily_returns
})

# Round returns to 4 decimal places
df['daily_return'] = df['daily_return'].round(4)

# Convert returns to percentages
df['daily_return'] = df['daily_return'] * 100

# Add day of week for verification
df['day_of_week'] = df['date'].dt.day_name()

# Print some statistics
print("\nData Statistics:")
print(f"Total number of days: {len(df)}")
print("\nDays by weekday:")
print(df['day_of_week'].value_counts().sort_index())
print("\nDate range:")
print(f"Start: {df['date'].min().strftime('%Y-%m-%d')}")
print(f"End: {df['date'].max().strftime('%Y-%m-%d')}")

# List of major US holidays for verification
major_holidays = [
    "New Year's Day",
    "Martin Luther King Jr. Day",
    "Presidents Day",
    "Memorial Day",
    "Independence Day",
    "Labor Day",
    "Thanksgiving",
    "Christmas"
]

# Save to CSV (excluding day_of_week column)
df[['date', 'daily_return']].to_csv('stock_data.csv', index=False)

# Sample of the data
print("\nFirst few rows of data:")
print(df[['date', 'daily_return']].head()) 