
# BACKEND API
This is the backend api for our application. It is written in python3 (3.8.10) and django rest framwork. Please make sure you have python3 installed on your machine and is accessible from your system environment path




## Installation

You will need to create and activate a python3 virtual environment to run this backend

```bash
 python3 -m venv myenv
```
To activate on windows
```bash
.\myenv\Scripts\activate
```
on Linux or macOS:
```bash
source myenv/bin/activate
```
To deactivate later:  
```bash
deactivate
```
After activating myenv, navigate to the project's main directory. Then, use pip to install the dependencies. Please wait a moment while all the packages are installed.
```bash
python3 -m pip install -r requirements.txt
```

## Run backend



Start venv and go to the project directory

```bash
source myenv/bin/activate
cd /PATH/TO/BACKEND_API
```

Make migrations (Note: whenever there is a database related error, run the following code as well, otherwise make migrations and migrate are only need to run once):
```bash
python3 manage.py makemigrations
python manage.py migrate --run-syncdb
python3 manage.py migrate
python3 manage.py runserver
```
Run server:
```bash
python3 manage.py runserver
```
