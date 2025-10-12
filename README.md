<p align="center">
  <img src="https://placehold.co/800x200/1D2B64/F8CDDA?text=AlienXFile+V2&font=inter" alt="AlienXFile V2 Banner"/>
</p>

<h1 align="center">AlienXFile V2 🚀</h1>

<p align="center">
  A secure, fast, and ephemeral file-sharing platform built with Flask and the Catbox.moe API.
</p>

<p align="center">
  <a href="https://www.python.org/" target="_blank"><img src="https://img.shields.io/badge/Python-3.11-blue" alt="Python Version"></a>
  <a href="https://flask.palletsprojects.com/" target="_blank"><img src="https://img.shields.io/badge/Flask-2.3-green" alt="Flask Version"></a>
  <a href="./LICENSE" target="_blank"><img src="https://img.shields.io/badge/License-MIT-yellow" alt="License"></a>
</p>

<p align="center">
  <strong><a href="https://alienxfilev2.pythonanywhere.com" target="_blank">View Live Demo »</a></strong>
</p>

---

## 📸 Showcase

<p align="center">
  <img width="45%" alt="Upload Page Screenshot" src="https://github.com/user-attachments/assets/8fc4eb3d-8229-4fe7-9ac5-856d2d4e7556" />
  &nbsp;&nbsp;&nbsp;&nbsp;
  <img width="45%" alt="Download Page Screenshot" src="https://github.com/user-attachments/assets/624ddd56-4846-4b30-987f-27800a5b036a" />
</p>

---

## 🌟 Key Features

- **Dual Upload Modes:** Share both files and raw text snippets seamlessly.
- **Secure & Ephemeral:** Files are temporary. No permanent storage on the server.
- **Unique Access Keys:** Auto-generated 4-digit keys for every upload.
- **Glassmorphism UI:** Modern, clean, and responsive design that works on any device.
- **Lightweight & Fast:** Built for speed with no unnecessary bloat.
- **Large File Support:** Handles uploads up to **200 MB** per file.

---

## 💻 Tech Stack

| Category     | Technology                                           |
|--------------|------------------------------------------------------|
| **Backend** | Python 3.11, Flask 2.x                               |
| **Frontend** | HTML5, CSS3 (Glassmorphism, Responsive Design)       |
| **Storage** | [Catbox.moe API](https://catbox.moe/)                |
| **Hosting** | PythonAnywhere, Render, Railway, etc.                |

---

## 💾 Get Started Locally

> **💻 Using Terminal / Command Line**
> ```bash
> # 1. Clone the repository
> git clone https://github.com/yourusername/AlienXFileV2.git
> cd AlienXFileV2
>
> # 2. Create a virtual environment
> python3 -m venv venv
>
> # 3. Activate the virtual environment
> # On Linux / Mac
> source venv/bin/activate
> # On Windows (PowerShell)
> # venv\Scripts\Activate.ps1
> # On Windows (Command Prompt)
> # venv\Scripts\activate.bat
>
> # 4. Install dependencies
> pip install -r requirements.txt
>
> # 5. Run the development server
> python app.py
> ```
>
> Open your browser and visit: [`http://127.0.0.1:5000`](http://127.0.0.1:5000)


---

## 🚀 Deployment

Deploying AlienXFile is straightforward. For platforms like **PythonAnywhere**:

1.  Upload your project files.
2.  Create a new web app and specify your Flask version.
3.  Set up your WSGI configuration file to point to the Flask app instance:
    > **📄 wsgi.py**
    > ```python
    > from app import app as application
    > ```
4.  Install the project dependencies from your SSH console:
    > **💻 Terminal**
    > ```bash
    > pip install -r requirements.txt
    > ```
5.  Reload the web app from your dashboard.

---

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

---

## 📄 License

This project is distributed under the MIT License. See `LICENSE` for more information.

<p align="center">
  Made with ❤️ by Aryan Kahar
</p>
