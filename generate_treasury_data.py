import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from pandas.tseries.holiday import USFederalHolidayCalendar

def generate_correlated_returns(stock_returns, target_correlation=0.1, 
                              treasury_vol=0.003,  # Lower volatility for Treasuries
                              treasury_mean=0.0001):  # Slightly positive mean return
    """Generate Treasury returns with specified correlation to stock returns"""
    
    # Generate base returns
    n = len(stock_returns)
    z1 = np.random.normal(0, 1, n)
    z2 = np.random.normal(0, 1, n)
    
    # Create correlated series
    x = z1
    y = target_correlation * z1 + np.sqrt(1 - target_correlation**2) * z2
    
    # Scale to desired properties
    treasury_returns = treasury_mean + treasury_vol * y
    
    # Add "flight to safety" effect
    extreme_stock_drops = stock_returns < np.percentile(stock_returns, 2)
    treasury_returns[extreme_stock_drops] *= -1  # Inverse relationship during stress
    
    return treasury_returns

# Set random seed for reproducibility
np.random.seed(42)

# Read stock data as reference
stock_data = pd.read_csv('stock_data.csv')
stock_data['date'] = pd.to_datetime(stock_data['date'])
stock_returns = stock_data['daily_return'].values / 100  # Convert from percentage

# Generate Treasury returns
treasury_returns = generate_correlated_returns(stock_returns)

# Create DataFrame
treasury_data = pd.DataFrame({
    'date': stock_data['date'],
    'daily_return': treasury_returns * 100  # Convert to percentage
})

# Round returns to 4 decimal places
treasury_data['daily_return'] = treasury_data['daily_return'].round(4)

# Calculate and print statistics
correlation = np.corrcoef(stock_returns, treasury_returns)[0,1]
print("\nData Statistics:")
print(f"Correlation with equities: {correlation:.4f}")
print(f"Treasury Daily Return Stats:")
print(f"Mean: {treasury_data['daily_return'].mean():.4f}%")
print(f"Std Dev: {treasury_data['daily_return'].std():.4f}%")
print(f"Min: {treasury_data['daily_return'].min():.4f}%")
print(f"Max: {treasury_data['daily_return'].max():.4f}%")

# Print sample of the data
print("\nFirst few rows of Treasury data:")
print(treasury_data.head())

# Save to CSV
treasury_data.to_csv('treasury_5y_data.csv', index=False)
print("\nData saved to treasury_5y_data.csv") 