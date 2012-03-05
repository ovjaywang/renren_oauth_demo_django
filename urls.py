from django.conf.urls.defaults import patterns, include, url

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('',
    url(r'^$', 'renren_oauth_demo.views.home', name='home'),
    url(r'^login/?$', 'renren_oauth_demo.views.renren_login', name='login'),
    url(r'^logout/?$', 'renren_oauth_demo.views.renren_logout', name='logout'),

    url(r'^status/new$', 'renren_oauth_demo.views.new_status', name='new_status'),
    url(r'^feed/new$', 'renren_oauth_demo.views.publish_feed', name='publish_feed'),

    # url(r'^renren_oauth_demo/', include('renren_oauth_demo.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),
)
