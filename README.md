# 🌈 Moodboard Lite

Moodboard Lite is a dynamic journaling React app that helps users capture their daily mood using emojis, GIFs, notes, and customizable colors. It features an intuitive, responsive UI with smooth animations and efficient state management.


## ✨ Features

- 😀 Add up to 5 emojis to describe your mood  
- 🎞️ Search and choose GIFs using Giphy integration with instant search results and also iamges upload with the url
- 🎨 Pick your favorite color theme for each mood entry
- 📝 Write a short note (limit 200 characters)
- 📅 View moodboards in an organized timeline grouped by month
- 🗑️ Delete moodboards easily
- 🔐 User Login and Signup with authentication
- ⚡ Global state management using Zustand
- 📱 Responsive design with smooth button animations on hover
- 📱 Dark/Light Mode

---

## 💻 Tech Stack

- Frontend: React 18, React Router DOM 7, Zustand
-	Backend: Express Js ,Node Js ,MongoDB ,JWT authentication 
-	Styling: CSS (custom, responsive, smooth gradients), button hover-animations
-	Emoji Picker: emoji-mart
-	GIF Search: Giphy API (via @giphy/js-fetch-api)
-	State Management: Zustand (for global state)
-	HTTP Client: axios

## Check the AppDemoScreenshots Folder for the demo

## ⚙️ Installation

### 1. Backend Setup

1.  **Create and Setup Server Directory**
    ```bash
    mkdir moodboard-lite && cd moodboard-lite
    mkdir server && cd server
    npm init -y
    ```

2.  **Install Dependencies**
    ```bash
    npm install express mongoose bcryptjs jsonwebtoken cors dotenv
    npm install --save-dev nodemon
    ```

3.  **Create Project Structure**
    ```bash
    mkdir models routes middleware
    ```

4.  **Configure Environment File (`server/.env`)**
    Create a file named `.env` in the `server` directory and add the following, updating the values as needed:
    ```
    MONGO_URI=mongodb://localhost:27017/moodboard-lite
    JWT_SECRET=your_super_secret_jwt_key_change_this
    PORT=5000
    ```

### 2. Frontend Setup

1.  **Create React App**
    Go back to the project root directory (`moodboard-lite`):
    ```bash
    cd ..
    npx create-react-app client
    cd client
    ```

2.  **Install Dependencies**
    ```bash
    npm install react-router-dom axios @emoji-mart/data @emoji-mart/react @giphy/js-fetch-api
    ```

3.  **Configure Environment File (`client/.env`)**
    Create a file named `.env` in the `client` directory and add your API keys:
    ```
    REACT_APP_API_URL=http://localhost:5000
    REACT_APP_GIPHY_API_KEY=your_giphy_api_key_here
    ```

4.  **Set up other folders** (e.g., components, pages, context, etc., as per your project design).

### 3. Running the Application

* Start the backend in the `server` directory: `npm start` (or a similar command set up in your `package.json`).
* Start the frontend in the `client` directory: `npm start`.

You will need to run these in two separate terminals.

---

## 🚀 Usage

1.  **Create and log in** to your account.
2.  **Create your daily moodboard** with emojis, GIFs, a color, and a note.
3.  **Browse your moodboard history** in the timeline.
4.  **Modify themes** and **manage** your mood entries with ease.


********





