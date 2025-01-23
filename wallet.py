import streamlit as st
import requests
import time
from web3 import Web3
import plotly.graph_objects as go
import plotly.express as px
import numpy as np
import pandas as pd
import networkx as nx

bright_colors = ['#FF007F', '#FFB400', '#00FF7F', '#00D9FF', '#FF7F00', '#FF00FF', '#FFFF00', '#00FF00']

# Set up your Etherscan and Infura API keys
INFURA_URL = "https://mainnet.infura.io/v3/5d419af494974b80a1d4579ac1109ee7"
ETHERSCAN_API_KEY = "E8VZXYAHZDM21WC5FX14UB75NUINQ98QJT"
WALLET_ADDRESS = "0x73f7b1184B5cD361cC0f7654998953E2a251dd58"
TRANSACTION_COUNT = 100  # Adjust the number of transactions to fetch
THRESHOLD_ETH = 10  # Set threshold for large transactions in ETH

# Set up Web3 instance to interact with the blockchain
web3 = Web3(Web3.HTTPProvider(INFURA_URL))

# Example of a set of blacklisted addresses
BLACKLISTED_ADDRESSES = {
    "0x0000000000000000000000000000000000000000",
    "0x1111111111111111111111111111111111111111"
}

# Function to fetch wallet balance from Etherscan
def get_balance(wallet_address):
    url = f"https://api.etherscan.io/api?module=account&action=balance&address={wallet_address}&tag=latest&apikey={ETHERSCAN_API_KEY}"
    response = requests.get(url)
    data = response.json()
    if data["status"] == "1":
        return int(data["result"]) / (10 ** 18)  # Convert from Wei to Ether
    else:
        print(f"Error fetching balance from Etherscan: {data['message']}")
        return 0.0

# Function to fetch recent transactions from Etherscan
def fetch_recent_transactions(wallet_address, count=10):
    url = f"https://api.etherscan.io/api?module=account&action=txlist&address={wallet_address}&startblock=0&endblock=99999999&page=1&offset={count}&sort=desc&apikey={ETHERSCAN_API_KEY}"
    response = requests.get(url)
    data = response.json()
    if data["status"] == "1":
        return data["result"][:count]  # Return the top `count` transactions
    else:
        print(f"Error fetching transactions from Etherscan: {data['message']}")
        return []

# Function to detect suspicious activity in transactions
def detect_suspicious_activity(transactions, wallet_creation_date, wallet_balance, threshold=THRESHOLD_ETH):
    suspicious_transactions = []
    activity_counts = {
        "Blacklisted Address": 0,
        "Self Transaction": 0,
        "Failed Transaction": 0,
        "High Gas Fee": 0,
        "Frequent Transaction": 0,
        "High Spend with Low Balance": 0,
        "Large Transaction": 0,
        "Large Transaction for New Wallet": 0,
        "Transaction Diversity": 0,
        "Repetitive Transactions": 0
    }

    unique_addresses = set()
    repeated_addresses = {}

    for tx in transactions:
        value_in_ether = int(tx["value"]) / (10 ** 18)
        gas_price_in_ether = int(tx["gasPrice"]) / (10 ** 18)
        gas_fee_in_ether = int(tx["gasUsed"]) * int(tx["gasPrice"]) / (10 ** 18) if "gasUsed" in tx else 0
        to_address = tx["to"].lower() if tx["to"] else None
        from_address = tx["from"].lower()

        # Check for blacklisted addresses
        if to_address in BLACKLISTED_ADDRESSES or from_address in BLACKLISTED_ADDRESSES:
            suspicious_transactions.append(
                {"issue": "Blacklisted Address", "details": f"Address: {to_address or from_address}", "tx_hash": tx["hash"]})
            activity_counts["Blacklisted Address"] += 1

        # Track unique and repeated addresses
        if to_address:
            unique_addresses.add(to_address)
            repeated_addresses[to_address] = repeated_addresses.get(to_address, 0) + 1

        # Check for suspicious patterns
        is_self_transaction = from_address == to_address
        is_failed_transaction = tx["isError"] == "1"
        is_high_fee = gas_fee_in_ether > (value_in_ether * 0.05)  # Fee > 5% of value
        is_frequent_tx = len(transactions) > 50  # Excessive transactions in a short time
        is_low_balance_high_spend = wallet_balance < 0.1 and value_in_ether > wallet_balance * 0.5  # High spend with low balance
        is_large_transaction = value_in_ether >= threshold
        is_new_wallet_large_tx = value_in_ether >= threshold and wallet_creation_date >= time.time() - 30 * 24 * 60 * 60  # Large TX for new wallets

        # Add suspicious transaction details
        if is_self_transaction:
            suspicious_transactions.append({"issue": "Self Transaction", "details": tx["to"], "tx_hash": tx["hash"]})
            activity_counts["Self Transaction"] += 1
        if is_failed_transaction:
            suspicious_transactions.append({"issue": "Failed Transaction", "details": "Transaction failed", "tx_hash": tx["hash"]})
            activity_counts["Failed Transaction"] += 1
        if is_high_fee:
            suspicious_transactions.append({"issue": "High Gas Fee", "details": f"Fee: {gas_fee_in_ether:.4f} ETH", "tx_hash": tx["hash"]})
            activity_counts["High Gas Fee"] += 1
        if is_frequent_tx:
            suspicious_transactions.append({"issue": "Frequent Transaction", "details": "Excessive transaction activity", "tx_hash": tx["hash"]})
            activity_counts["Frequent Transaction"] += 1
        if is_low_balance_high_spend:
            suspicious_transactions.append({"issue": "High Spend with Low Balance", "details": f"Value: {value_in_ether:.4f} ETH", "tx_hash": tx["hash"]})
            activity_counts["High Spend with Low Balance"] += 1
        if is_large_transaction:
            suspicious_transactions.append({"issue": "Large Transaction", "details": f"Value: {value_in_ether:.4f} ETH", "tx_hash": tx["hash"]})
            activity_counts["Large Transaction"] += 1
        if is_new_wallet_large_tx:
            suspicious_transactions.append({"issue": "Large Transaction for New Wallet", "details": f"Value: {value_in_ether:.4f} ETH", "tx_hash": tx["hash"]})
            activity_counts["Large Transaction for New Wallet"] += 1

    # Check for transaction diversity (too many unique addresses)
    if len(unique_addresses) > 100:
        suspicious_transactions.append({"issue": "Transaction Diversity", "details": f"Interacted with {len(unique_addresses)} unique addresses"})
        activity_counts["Transaction Diversity"] += 1

    # Check for repetitive patterns (too many interactions with the same address)
    for address, count in repeated_addresses.items():
        if count > 10:  # Arbitrary threshold for repetitive transactions
            suspicious_transactions.append({"issue": "Repetitive Transactions", "details": f"Repeated interactions with {address} ({count} times)"})
            activity_counts["Repetitive Transactions"] += 1

    return suspicious_transactions, activity_counts

# Function to plot pie chart with animation
def plot_pie_chart(activity_counts):
    labels = list(activity_counts.keys())
    values = list(activity_counts.values())
    
    fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=0.4, pull=[0.1]*len(values), 
                                 rotation=90, marker=dict(colors=bright_colors))])
    
    fig.update_traces(hoverinfo='label+percent', textinfo='value', textfont_size=20, 
                      hoverlabel=dict(bgcolor="rgba(0, 0, 0, 0.7)", font_size=16, font_color="white"))
    
    fig.update_layout(
        title="Distribution of Security Issues",
        title_x=0.5,
        transition_duration=500,
        transition_easing="cubic-in-out",
        autosize=True,
        plot_bgcolor="#2E3440",  # Dark background color for the chart
        paper_bgcolor="#2E3440",
        font=dict(family="Roboto, sans-serif", color="white"),
        margin=dict(l=0, r=0, b=0, t=40)
    )
    st.plotly_chart(fig, use_container_width=True)


# Additional Visualizations (Bar chart, Heatmap, Histogram, etc.)

# Plot bar chart of transaction values
def plot_transaction_value_bar_chart(transactions):
    values = [int(tx["value"]) / 10**18 for tx in transactions]
    tx_hashes = [tx["hash"] for tx in transactions]

    fig = go.Figure(data=[go.Bar(x=tx_hashes, y=values, marker=dict(color=bright_colors[1]))])
    
    fig.update_layout(
        title="Transaction Values",
        xaxis_title="Transaction Hash",
        yaxis_title="ETH",
        plot_bgcolor="#2E3440",
        paper_bgcolor="#3B4252",
        font=dict(family="Roboto, sans-serif", color="white"),
        showlegend=False
    )
    st.plotly_chart(fig, use_container_width=True)

# Plot heatmap for transaction times
def plot_transaction_heatmap(transactions):
    times = [int(tx["timeStamp"]) for tx in transactions]
    times = pd.to_datetime(times, unit='s')
    hours = times.hour

    fig = px.histogram(hours, x=hours, nbins=24, color_discrete_sequence=bright_colors)
    fig.update_layout(
        title="Transaction Activity Heatmap (Hour of the Day)",
        xaxis_title="Hour of Day",
        yaxis_title="Transaction Count",
        plot_bgcolor="#2E3440",
        paper_bgcolor="#3B4252",
        font=dict(family="Roboto, sans-serif", color="white")
    )
    st.plotly_chart(fig, use_container_width=True)

# Plot spend vs balance line chart
def plot_spend_vs_balance(transactions, wallet_balance):
    spend = [int(tx["value"]) / 10**18 for tx in transactions]
    dates = [pd.to_datetime(int(tx["timeStamp"]), unit='s') for tx in transactions]
    
    df = pd.DataFrame({
        'Date': dates,
        'Spend': spend,
        'Balance': [wallet_balance] * len(transactions)
    })
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=df['Date'], y=df['Spend'], mode='lines', name='Spend', line=dict(color=bright_colors[0])))
    fig.add_trace(go.Scatter(x=df['Date'], y=df['Balance'], mode='lines', name='Balance', line=dict(color=bright_colors[4])))
    
    fig.update_layout(
        title="Spend vs Balance",
        xaxis_title="Date",
        yaxis_title="ETH",
        plot_bgcolor="#2E3440",
        paper_bgcolor="#3B4252",
        font=dict(family="Roboto, sans-serif", color="white")
    )
    st.plotly_chart(fig, use_container_width=True)
    
import pandas as pd

def plot_transaction_count_over_time(transactions):
    times = [int(tx["timeStamp"]) for tx in transactions]
    times = pd.to_datetime(times, unit='s')

    times_dates = pd.Series(times.date)

    transaction_counts = times_dates.value_counts().sort_index()

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=transaction_counts.index, y=transaction_counts.values, mode='lines', 
                             name='Transaction Count', line=dict(color=bright_colors[3], width=4)))

    fig.update_layout(
        title="Transaction Count Over Time",
        xaxis_title="Date",
        yaxis_title="Number of Transactions",
        plot_bgcolor="#2E3440",
        paper_bgcolor="#3B4252",
        font=dict(family="Roboto, sans-serif", color="white")
    )
    st.plotly_chart(fig, use_container_width=True)




# 2. Plot top 5 largest transactions (Bar Chart)
def plot_top_5_largest_transactions(transactions):
    transactions_sorted = sorted(transactions, key=lambda tx: int(tx["value"]), reverse=True)[:5]
    values = [int(tx["value"]) / 10**18 for tx in transactions_sorted]
    tx_hashes = [tx["hash"] for tx in transactions_sorted]
    
    fig = go.Figure(data=[go.Bar(x=tx_hashes, y=values, marker=dict(color='#81A1C1'))])
    fig.update_layout(
        title="Top 5 Largest Transactions",
        xaxis_title="Transaction Hash",
        yaxis_title="ETH",
        plot_bgcolor="#2E3440",
        paper_bgcolor="#3B4252",
        font=dict(family="Roboto, sans-serif", color="white"),
        showlegend=False,
    )
    st.plotly_chart(fig, use_container_width=True)

# 3. Plot transaction value distribution (Histogram)
def plot_transaction_value_distribution(transactions):
    values = [int(tx["value"]) / 10**18 for tx in transactions]

    fig = px.histogram(values, nbins=50, color_discrete_sequence=["#81A1C1"])
    fig.update_layout(
        title="Transaction Value Distribution",
        xaxis_title="Transaction Value (ETH)",
        yaxis_title="Frequency",
        plot_bgcolor="#2E3440",
        paper_bgcolor="#3B4252",
        font=dict(family="Roboto, sans-serif", color="white")
    )
    st.plotly_chart(fig, use_container_width=True)

# 4. Plot gas fee distribution (Histogram)
def plot_gas_fee_distribution(transactions):
    gas_fees = [int(tx["gasUsed"]) * int(tx["gasPrice"]) / (10**18) for tx in transactions]

    fig = px.histogram(gas_fees, nbins=50, color_discrete_sequence=[bright_colors[2]])
    fig.update_layout(
        title="Gas Fee Distribution",
        xaxis_title="Gas Fee (ETH)",
        yaxis_title="Frequency",
        plot_bgcolor="#2E3440",
        paper_bgcolor="#3B4252",
        font=dict(family="Roboto, sans-serif", color="white")
    )
    st.plotly_chart(fig, use_container_width=True)

# 5. Plot cumulative transaction value over time (Line Chart)
def plot_cumulative_transaction_value(transactions):
    times = [int(tx["timeStamp"]) for tx in transactions]
    values = [int(tx["value"]) / 10**18 for tx in transactions]
    times = pd.to_datetime(times, unit='s')

    cumulative_values = np.cumsum(values)

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=times, y=cumulative_values, mode='lines', name='Cumulative Value', 
                             line=dict(color=bright_colors[5], width=4)))
    fig.update_layout(
        title="Cumulative Transaction Value Over Time",
        xaxis_title="Date",
        yaxis_title="Cumulative ETH",
        plot_bgcolor="#2E3440",
        paper_bgcolor="#3B4252",
        font=dict(family="Roboto, sans-serif", color="white")
    )
    st.plotly_chart(fig, use_container_width=True)

# 6. Plot Address Interaction Network (Force-Directed Graph)
def plot_address_interaction_network(transactions):
    G = nx.Graph()

    for tx in transactions:
        from_address = tx["from"].lower()
        to_address = tx["to"].lower() if tx["to"] else None
        G.add_edge(from_address, to_address)

    pos = nx.spring_layout(G, seed=42)
    edges_x = []
    edges_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edges_x.append(x0)
        edges_x.append(x1)
        edges_y.append(y0)
        edges_y.append(y1)

    edge_trace = go.Scatter(x=edges_x, y=edges_y, mode='lines', line=dict(width=0.5, color=bright_colors[6]), 
                            hoverinfo='none')

    nodes_x = [pos[node][0] for node in G.nodes()]
    nodes_y = [pos[node][1] for node in G.nodes()]
    node_trace = go.Scatter(x=nodes_x, y=nodes_y, mode='markers', hoverinfo='text', 
                            marker=dict(color=bright_colors[7], size=10))

    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(
        title="Address Interaction Network",
        title_x=0.5,
        plot_bgcolor="#2E3440",
        paper_bgcolor="#3B4252",
        font=dict(family="Roboto, sans-serif", color="white"),
        showlegend=False
    )
    st.plotly_chart(fig, use_container_width=True)


# 7. Plot transaction frequency over time (Line Chart)
def plot_cumulative_transaction_value(transactions):
    times = [int(tx["timeStamp"]) for tx in transactions]
    values = [int(tx["value"]) / 10**18 for tx in transactions]
    times = pd.to_datetime(times, unit='s')

    # Calculate cumulative value
    cumulative_values = np.cumsum(values)

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=times, 
        y=cumulative_values, 
        mode='lines', 
        name='Cumulative Value', 
        line=dict(color='#81A1C1', width=4, dash='dot')
    ))

    fig.update_layout(
        title="Cumulative Transaction Value Over Time",
        xaxis_title="Date",
        yaxis_title="Cumulative ETH",
        plot_bgcolor="#2E3440",  # Dark background
        paper_bgcolor="#3B4252",  # Lighter background for contrast
        font=dict(family="Roboto, sans-serif", color="white"),
        hoverlabel=dict(font_size=18, font_color="white"),
        transition_duration=1000,
        transition_easing="cubic-in-out"
    )
    st.plotly_chart(fig, use_container_width=True)

# 8. Plot Transaction Value Trend (Line Chart)
def plot_transaction_value_trend(transactions):
    times = [int(tx["timeStamp"]) for tx in transactions]
    values = [int(tx["value"]) / 10**18 for tx in transactions]
    times = pd.to_datetime(times, unit='s')

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=times, y=values, mode='lines+markers', name='Transaction Value Trend',
                             line=dict(color=bright_colors[5], width=3), marker=dict(size=6, color=bright_colors[1])))

    fig.update_layout(
        title="Transaction Value Trend Over Time",
        xaxis_title="Date",
        yaxis_title="ETH",
        plot_bgcolor="#2E3440",
        paper_bgcolor="#3B4252",
        font=dict(family="Roboto, sans-serif", color="white")
    )
    st.plotly_chart(fig, use_container_width=True)

def plot_transaction_success_rate(transactions):
    successful = 0
    failed = 0

    for tx in transactions:
        if tx["isError"] == "0":
            successful += 1
        else:
            failed += 1

    fig = go.Figure(data=[go.Pie(labels=["Successful", "Failed"], values=[successful, failed], hole=0.3,
                                 marker=dict(colors=[bright_colors[0], bright_colors[3]]))])
    
    fig.update_layout(
        title="Transaction Success vs Failure",
        plot_bgcolor="#2E3440",
        paper_bgcolor="#3B4252",
        font=dict(family="Roboto, sans-serif", color="white")
    )
    st.plotly_chart(fig, use_container_width=True)
    
# 9. Plot Transaction Activity Over Time (Line Chart)
def plot_transaction_activity_timeline(transactions):
    times = [int(tx["timeStamp"]) for tx in transactions]
    times = pd.to_datetime(times, unit='s')

    # Calculate daily transaction counts
    daily_activity = pd.Series(times).dt.date.value_counts().sort_index()

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=daily_activity.index, y=daily_activity.values, mode='lines+markers', 
                             name="Daily Transaction Activity", line=dict(color=bright_colors[4], width=3)))

    fig.update_layout(
        title="Transaction Activity Over Time",
        xaxis_title="Date",
        yaxis_title="Number of Transactions",
        plot_bgcolor="#2E3440",
        paper_bgcolor="#3B4252",
        font=dict(family="Roboto, sans-serif", color="white")
    )
    st.plotly_chart(fig, use_container_width=True)
    
    
    


# Main script using Streamlit to create a simple web app
if __name__ == "__main__":
    # Add custom CSS to set blockchain.jpg as the background
    st.markdown("""<style>
        body {
            background-image: 'blockchain.jpg';  # Path to your image
            background-size: cover;  # Ensure the image covers the entire page
            background-position: center center;  # Center the image
            background-attachment: fixed;  # Keep the image fixed while scrolling
            font-family: 'Roboto', sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            color: white;
        }

        h1 {
            font-size: 3rem;
            font-weight: bold;
            text-shadow: 0 0 20px rgba(0, 255, 255, 0.8);
        }

        .wallet-balance {
            font-size: 40px;
            font-weight: bold;
            color: #A3BE8C;
            margin-top: 20px;
            text-align: center;
            animation: bounce 2s infinite ease-in-out;
        }

        .stButton>button {
            background-color: #81A1C1;
            color: white;
            border-radius: 10px;
            padding: 15px 30px;
            font-size: 18px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
            transition: all 0.4s ease;
        }

        .stButton>button:hover {
            background-color: #5E81AC;
            transform: scale(1.1);
        }

        .st-expanderHeader {
            font-size: 18px;
            color: #ECEFF4;
            font-weight: 600;
        }

        .st-expanderContent {
            font-size: 14px;
            color: #D8DEE9;
        }

        @keyframes bounce {
            0%, 100% {
                transform: translateY(0);
            }
            50% {
                transform: translateY(-20px);
            }
        }
    </style>""", unsafe_allow_html=True)



    # Title and wallet address input
    st.title("Ethereum Wallet Activity Monitor")

    wallet_address_input = st.text_input("Enter Ethereum Wallet Address", value=WALLET_ADDRESS)

    if 'history' not in st.session_state:
        st.session_state['history'] = []

    if wallet_address_input:
        with st.spinner("Fetching wallet data..."):
            balance = get_balance(wallet_address_input)
            recent_transactions = fetch_recent_transactions(wallet_address_input, count=TRANSACTION_COUNT)
            wallet_creation_date = time.time() - 365 * 24 * 60 * 60  # Example: wallet created a year ago
            suspicious_activities, activity_counts = detect_suspicious_activity(recent_transactions, wallet_creation_date, balance)

        st.markdown(f'<div class="wallet-balance">Wallet Balance: {balance:.4f} ETH</div>', unsafe_allow_html=True)

        # Add this wallet's details to history
        st.session_state['history'].append({
            'wallet': wallet_address_input,
            'balance': balance,
            'activity_counts': activity_counts,
            'suspicious_activities': suspicious_activities
        })

        # Show suspicious activity
        if suspicious_activities:
            st.write("\n**Suspicious Activity Detected:**")
            for activity, count in activity_counts.items():
                with st.expander(f"{activity} ({count})"):
                    st.write(f"Details of {activity}:")
                    relevant_activities = [tx for tx in suspicious_activities if tx['issue'] == activity]
                    for tx in relevant_activities:
                        st.write(f"- {tx['details']} (Tx Hash: {tx.get('tx_hash', 'N/A')})")

 # --- New Table for Recent Transactions ---
    # Prepare the data for the table
    import pandas as pd

# Prepare the data for the table
import pandas as pd

# Prepare the data for the table
transaction_data = []
for tx in recent_transactions:
    value_in_ether = int(tx["value"]) / (10 ** 18)
    gas_price_in_ether = int(tx["gasPrice"]) / (10 ** 18)
    gas_fee_in_ether = int(tx["gasUsed"]) * gas_price_in_ether if "gasUsed" in tx else 0
    
    transaction_data.append({
        'Tx Hash': tx['hash'],
        'From Address': tx['from'],
        'To Address': tx['to'],
        'Value (ETH)': f"{value_in_ether:.4f}",
        'Gas Price (ETH)': f"{gas_price_in_ether:.10f}",
        'Gas Used (ETH)': f"{gas_fee_in_ether:.10f}",
        'Transaction Status': 'Success' if tx["isError"] == "0" else 'Failed'
    })

# Convert the list of transactions to a pandas DataFrame
transaction_df = pd.DataFrame(transaction_data)

# Apply pandas styling to make the table visually appealing and set column widths
styled_df = transaction_df.style.set_properties(
    **{
        'font-size': '16px',   # Increase font size
        'text-align': 'center',  # Center align the text in each column
        'background-color': '#000000',  # Set the background color of the table to black
        'color': '#FF0000',  # Red text color
        'border': '1px solid #ddd',  # Add borders around the cells
        'border-collapse': 'collapse',  # Collapse borders
        'padding': '10px',  # Increase padding for cells
    }
).set_table_styles(
    [{
        'selector': 'thead th', 
        'props': [('background-color', '#333333'),  # Dark background color for header
                  ('color', 'white'),  # Header text color
                  ('font-size', '18px'),  # Header font size
                  ('padding', '15px')]}]  # Add padding to header cells
)

# Set max-width and make it responsive
styled_df = styled_df.set_properties(
    subset=['Tx Hash', 'From Address', 'To Address', 'Value (ETH)', 'Gas Price (ETH)', 'Gas Used (ETH)', 'Transaction Status'],
    **{'max-width': '250px', 'overflow': 'hidden'}
)

# Add custom CSS to make the table fit the available width without scrolling
st.markdown("""
    <style>
        .stDataFrame {
            width: 100%;  # Ensure the table takes up full width
            overflow: hidden;  # Prevent horizontal scroll
            white-space: nowrap;  # Prevent text from overflowing
        }
        .stDataFrame th, .stDataFrame td {
            max-width: 200px;  # Set column width limits
            text-overflow: ellipsis;  # Ensure text gets truncated if too long
            overflow: hidden;
            word-wrap: break-word;
        }
        .stDataFrame th {
            font-size: 18px;
            background-color: #333333;  # Dark background color for header
            color: white;  # White text color for header
        }
        .stDataFrame td {
            font-size: 16px;
            color: #FF0000;  # Red text color for the body of the table
        }
    </style>
""", unsafe_allow_html=True)

# Show the styled DataFrame in Streamlit
st.write("### Recent Transactions")
st.dataframe(styled_df)

# Visualization & Security checks (optional as per your existing code)
st.sidebar.header("Security Issues Distribution")
plot_pie_chart(activity_counts)
plot_transaction_value_bar_chart(recent_transactions)
plot_transaction_heatmap(recent_transactions)
plot_spend_vs_balance(recent_transactions, balance)
plot_transaction_count_over_time(recent_transactions)
plot_top_5_largest_transactions(recent_transactions)
plot_transaction_value_distribution(recent_transactions)
plot_gas_fee_distribution(recent_transactions)
plot_cumulative_transaction_value(recent_transactions)
plot_address_interaction_network(recent_transactions)
plot_transaction_value_trend(recent_transactions)
plot_transaction_success_rate(recent_transactions)
plot_transaction_activity_timeline(recent_transactions)

# Show history on the left sidebar
if st.session_state['history']:
    st.sidebar.header("Wallet History")
    for entry in st.session_state['history']:
        with st.sidebar.expander(f"Wallet: {entry['wallet']}"):
            st.write(f"Balance: {entry['balance']:.4f} ETH")
            for activity, count in entry['activity_counts'].items():
                st.write(f"{activity}: {count} occurrences")
            for tx in entry['suspicious_activities']:
                st.write(f"- {tx['issue']}: {tx['details']}")
