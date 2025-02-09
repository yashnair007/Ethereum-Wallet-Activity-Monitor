Ethereum Wallet Activity Monitor

📜 Project Overview
The Ethereum Wallet Activity Monitor is a user-friendly web-based tool for monitoring Ethereum wallet activities, visualizing transaction patterns, and detecting suspicious activities. This tool provides wallet owners and blockchain enthusiasts with actionable insights about their wallet's performance and security.

🚀 Features
Wallet Balance Visualization
Displays the current ETH balance in a visually engaging format.

Transaction Success Rate
Shows a pie chart illustrating the success and failure rates of transactions.

Activity Timeline
Line chart representing transaction activity over time.

Suspicious Activity Detection
Identifies and flags potential security threats based on wallet activity patterns.

Comprehensive Transaction Table
Detailed and styled transaction history, including gas fees, value transferred, and status.

Email Alerts
Sends email notifications for critical updates or reports using Gmail SMTP.

Responsive UI
A sleek and intuitive interface built with Streamlit and custom CSS for seamless user experience.

🛠️ Technologies Used
Frontend: Streamlit for building the web interface.

Visualization: Plotly for creating dynamic and interactive charts.

Blockchain Interaction: Etherscan API for retrieving wallet data and transactions.

Email Notifications: smtplib and email.mime for automated email reporting.

Data Handling: Pandas for efficient data processing.

Custom Styling: HTML and CSS for enhanced UI/UX.

📋 Setup Instructions
Prerequisites
Python 3.8 or higher
Etherscan API Key
Gmail account with an app password for email notifications

Installation

Etherscan API Key
Replace the placeholder in the code with your API key.
Email Credentials
Add your Gmail address and app password in the send_email() function.

Run the Streamlit app:

streamlit run app.py
⚡ Usage
Open the app in your browser after running it locally.
Enter an Ethereum wallet address to retrieve and analyze data.
Explore detailed visualizations, suspicious activity alerts, and transaction insights.
(Optional) Enable email alerts for receiving updates and reports.

🖼️ Visualizations
Pie Chart: Transaction success vs. failure rates.
Line Chart: Daily transaction activity over time.
Table: Comprehensive transaction details.


✨ Future Enhancements
Add multi-chain support for other blockchains like Binance Smart Chain (BSC) or Polygon.
Integrate advanced analytics using machine learning.
Build a mobile-friendly version of the app.
Deploy the app using services like AWS, Heroku, or Streamlit Cloud.

📧 Contact
For questions or feedback, reach out to:
Name: Yash 
Email: yashputhalath123@gmail.com
