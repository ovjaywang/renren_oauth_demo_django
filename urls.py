from django.conf.urls.defaults import patterns, include, url

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('',
    url(r'^$', 'renren_oauth_demo.views.home', name='home'),
    url(r'^auth/login$', 'renren_oauth_demo.views.login', name='login'),
    url(r'^auth/logout$', 'renren_oauth_demo.views.logout', name='logout'),

    # url(r'^renren_oauth_demo/', include('renren_oauth_demo.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),
)
