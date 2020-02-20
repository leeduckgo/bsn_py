"""bsn URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from bsn_test import views
from django.conf.urls import url

urlpatterns = [
	path('admin/', admin.site.urls),
	url(r'^index/$', views.save),
	url(r'^$', views.save),
	url(r'^save/$', views.save),
	url(r'^get/$', views.get),
	url(r'^update/$', views.update),
	url(r'^delete/$', views.delete),
	url(r'^save_data/$', views.save_data),
	url(r'^get_data/$', views.get_data),
	url(r'^update_data/$', views.update_data),
	url(r'^delete_data/$', views.delete_data),
]
