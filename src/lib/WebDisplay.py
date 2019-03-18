#!/usr/bin/env python3.3
# -*- coding: utf8 -*-
#
# Imports

import os
_runpath=os.path.dirname(os.path.realpath(__file__))

import re
from urllib.request import urlopen
import urllib
try:
  from flask import Flask, render_template, jsonify
except:
  sys.exit("Missing dependencies!")

import json

from lib.Toolkit import make_dict, toLocalTime, toHuman, fromEpoch
from lib.Config import Configuration

class WebDisplay(object):
  @classmethod
  def start(self,port=None,scan=None):
    app = Flask(__name__, static_folder='static', static_url_path='/static')
    # functions
    # routes
    ######################################################
    #WEB UI for Safe Dogs
    @app.route('/')
    def zwyx_dd_view():
        return render_template('index1.html')
    @app.route('/ssh')
    def ssh():
        return render_template("ssh.html")
    @app.route('/first')
    def showjson():
        SITE_ROOT = os.path.realpath(os.path.dirname(__file__))
        json_url = os.path.join(SITE_ROOT, "static/temp", "counting_attack_type")
        data = json.load(open(json_url))
        return jsonify(data)
    @app.route('/third')
    def thirdjson():
        SITE_ROOT = os.path.realpath(os.path.dirname(__file__))
        json_url = os.path.join(SITE_ROOT, "static/temp", "counting_attack_type")
        data = json.load(open(json_url))
        return jsonify(data)
    @app.route('/second')
    def secondjson():
        SITE_ROOT = os.path.realpath(os.path.dirname(__file__))
        json_url = os.path.join(SITE_ROOT, "static/temp", "counting_ip")
        data = json.load(open(json_url))
        return jsonify(data['data'])    
    ##########################################################

    @app.route('/report')
    def index():
      return render_template('index.html', scan=scan)

    @app.route('/cve/<cveid>')
    def cve(cveid):
      host,port=Configuration.getCVESearch()
      data = (urlopen('http://%s:%s/api/cve/%s'%(host,port,cveid)).read()).decode('utf8')
      cvejson=json.loads(str(data))
      if cvejson is {}:
        return page_not_found(404)
      return render_template('cve.html', cve=cvejson)

    # error handeling
    @app.errorhandler(404)
    def page_not_found(e):
      return render_template('404.html'), 404

    # filters
    @app.template_filter('product')
    def product(banner):
      if banner:
        r=make_dict(banner)
        return r['product'] if 'product' in r else 'unknown'
      else:
        return "unknown"
    @app.template_filter('toHuman')
    def humanify(cpe):
      return toHuman(cpe)

    @app.template_filter('currentTime')
    def currentTime(utc):
      return toLocalTime(utc)

    @app.template_filter('impact')
    def impact(string):
      if string.lower() == 	"none":       return "good"
      elif string.lower() == "partial":  return "medium"
      elif string.lower() == "complete": return "bad"

    @app.template_filter('vFeedName')
    def vFeedName(string):
      string=string.replace('map_','')
      string=string.replace('cve_','')
      return string.title()

    @app.template_filter('htmlEncode')
    def htmlEncode(string):
      return urllib.parse.quote_plus(string).lower()

    @app.template_filter('isURL')
    def isURL(string):
      urlTypes= [re.escape(x) for x in ['http://','https://', 'www.']]
      return re.match("^(" + "|".join(urlTypes) + ")", string)

    @app.template_filter('fromEpoch')
    def fromEpoch_filter(epoch):
      return fromEpoch(epoch)


    # debug filter
    @app.template_filter('type')
    def isType(var):
      return type(var)

    #start webserver
    host = Configuration.getFlaskHost()
    port = Configuration.getFlaskPort()
    debug = Configuration.getFlaskDebug()
    app.run(host=host, port=port, debug=debug)


