
Overview
========
This FastAPI project allows users to register, authenticate and modify their user profile infos


Content
=======
- Features
- Versionning
- Dependencies
- Deployment
- Challenges and known bugs
- Future additions and improvements


Features
========
- user authentification
- user profile personnalization


Versionning
===========
v0.0.0
- user register
- user login
v0.0.1
- user profile
v0.0.2
- email verification (using mail trap)


Dependencies
============

# Python version
python==3.10.4

# Super Packages
fastapi==0.81.0
uvicorn==0.18.3
tortoise-orm==0.19.2
python-multipart==0.0.5
passlib==1.7.4
bcrypt==4.0.0
pyjwt==2.4.0

Deployment
==========
hypercorn main:app --reload


Challenge and known bugs
========================

None.


Future additions and improvements
=================================
- Dockerization

