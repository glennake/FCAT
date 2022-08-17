# FCAT
Fortinet Contract Automation Tool (FCAT) is a Python application to assist with bulk parsing of Fortinet contract ZIP files and registration of Fortinet products and services using Fortinet's FortiCare API.

## Platform Support and Requirements

### Python

Tested on MacOS Monterey and Microsoft Windows 10 21H2

#### Requirements

- Python 3.10  
- keyring  
- openpyxl  
- PyPDF2==1.27.5  
- PySimpleGUI  
- requests  
- traceback-with-variables  

#### Usage

1. Ensure that [Python 3.10+](https://www.python.org/downloads/) is installed for your platform.

2. Ensure that [Git](https://git-scm.com/downloads) is installed for your platform.

3. Clone the repository

```git clone https://github.com/glennake/FCAT.git```

4. Enter the created directory containing the Git repository clone

```cd FCAT```

2. Run FCAT with Python:

```python FCAT/FCAT.py```

### Distributable

Tested on Microsoft Windows 10 21H2

#### Requirements

All required dependancies are packaged within the distributable EXE file.

## Build Your Own EXE

If you are uncomfortable running the packaged EXE in this repository, you can build your own for peace of mind. Instructions on how to do this using Nuitka are provided below.

Nuitka is cross platform so the build should work on any platforms that it supports. However, Nuitka does not output cross platform binaries, therefore you must perform the build process on each platform that you wish to build a binary for individually.

### Windows

1. Ensure that [Python 3.10+](https://www.python.org/downloads/windows/) is installed on your Windows machine.

2. Ensure that [Git](https://git-scm.com/download/win) is installed on your Windows machine.

3. Clone the repository

```git clone https://github.com/glennake/FCAT.git```

4. Enter the created directory containing the Git repository clone

```cd FCAT```

2. Install all dev requirements using pip:

```pip install -r requirements-dev.txt```

3. Run the build process using Nuitka

```python -m nuitka --standalone --onefile --include-module="win32timezone" --include-module="win32cred" --enable-plugin=tk-inter --windows-disable-console --output-dir=dist FCAT/FCAT.py```
