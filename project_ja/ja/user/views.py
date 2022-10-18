import email
from unicodedata import name
from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.models import User
import requests
import pandas as pd
import json

from .models import Student
# Create your views here.


def index(request):
    if request.user.is_authenticated:
        return render(request, 'user/home.html')
    return redirect("/login")


def login_view(request):
    if request.user.is_authenticated:
        return render(request, 'user/home.html')
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)

        if user is not None and user.is_superuser:
            login(request, user)
            return redirect("/admin")

        else:

            login_status = login_api(username, password)

            if login_status == 200:
                user = authenticate(
                    request, username=username, password=password)

                if not request.user.is_authenticated:
                    header = {
                        'Content-Type': 'application/json',
                        'Application-Key': 'TUdad3354636aacf9e1e7f8954bef241f8dd654708036bf06bf8ae703785b21bc985327cf4b0059571504984688553db30'
                    }
                    pull_api = requests.get(
                        'https://restapi.tu.ac.th/api/v2/profile/std/info/?id='+str(username), headers=header)
                    data_student = json.loads(pull_api.content).get("data")
                    first_name, surname = (
                        data_student["displayname_th"]).split(" ")
                    email = data_student["email"]
                    user = User.objects.create_user(username=username,
                                                    password=password,
                                                    first_name=first_name,
                                                    last_name=surname,
                                                    email=email)
                    user.save()

                if user is not None:
                    login(request, user)
                    return redirect("/")

            else:
                messages.info(request, "invalid Student ID or password")
    return render(request, 'user/login.html')


def logout_view(request):
    logout(request)
    messages.success(request, "Logged out.")
    return render(request, "user/login.html", {
        "messages": messages.get_messages(request)
    })


# login with tu api
def login_api(username, password):
    header = {
        'Content-Type': 'application/json',
        'Application-Key': 'TUdad3354636aacf9e1e7f8954bef241f8dd654708036bf06bf8ae703785b21bc985327cf4b0059571504984688553db30'
    }

    body = {"UserName": username, "PassWord": password}

    res = requests.post(
        "https://restapi.tu.ac.th/api/v1/auth/Ad/verify", headers=header, json=body)

    return res.status_code
