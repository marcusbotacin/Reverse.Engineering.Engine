#!/usr/bin/env python3

# RevEngE - A trace-based decompiler for reverse engineer
# Author: Marcus Botacin
# Supporter: Lucas Galante
# Creation: UFPR, 2018

# Import Block
from googlesearch import search     # Search Google for URL
import requests                     # Crawl web pages
import sys                          # Receive args -- test only
import pickle                       # load/store introspected functions

# Class which represents an external function
class External_Function():
    def __init__(self,name,lib,prototype):
        self.set_name(name)             # function name
        self.set_lib(lib)               # library function is inside
        self.set_prototype(prototype)   # fuction prototype
        self.get_n_args()               # parse arguments

    # Setters and Getters

    # set function name
    def set_name(self,name):
        self.name=name

    # get function name
    def get_name(self):
        return self.name

    # set library name
    def set_lib(self,lib):
        self.lib=lib

    # get library name
    def get_lib(self):
        return self.lib

    # get number of arguments
    def get_n_args(self):
        # first, parse the arguments
        self.get_args()
        # then get the list size
        self.n_args=len(self.args)
        return self.n_args

    # get arguments
    def get_args(self):
        # empty arg list
        arg_list=[]
        # for each argument (comma separated)
        for arg in self.prototype.split("(")[1].split(","):
            # INT-like
            if "int" in arg or "size_t" in arg:
                arg_list.append("int")
            # CHAR
            elif "char" in arg:
                arg_list.append("char")
            # ANY OTHER
            else:
                arg_list.append("Other")
        self.args=arg_list
        return self.args

    # set function return type
    def set_return(self,freturn):
        self.freturn=freturn

    # get function return type
    def get_return(self):
        try:
            return self.freturn
        except:
            return None

    # set function prototype
    def set_prototype(self,prototype):
        self.prototype=prototype
        # set return type
        self.set_return(self.prototype.strip().split(" ")[0])

    # get function prototype
    def get_name(self):
        return self.name

    # Print, for debugging purposes
    def show(self):
        print("%s@%s: %s (Return: %s) (N_Args: %d)" % (self.name,self.lib,self.prototype,self.freturn,self.n_args))
        print("Args: ",self.get_args())

# Instropection -- external function management
class Introspection_Manager():
    # instantiation
    def __init__(self):
        # load function database
        self.load_db()

    # load function database method
    def load_db(self):
        # try to open database file
        try:
            f = open("introspection.db","rb")
        except:
            # case no file, empty database
            self.db = []
            return

        # if having file, try to interpret it as function database
        try:
            # if success, load
            self.db = pickle.load(f)
        except:
            # otherwise, empty database
            self.db = []

    # add a given function to the database
    def store_db(self,function):
        # open/create database file
        f = open("introspection.db","wb")
        # append function to in-memory database
        self.db.append(function)
        # add/flush in-memory database to the disk
        pickle.dump(self.db,f)
        f.close()

    # retrieve page from url
    def get_web_page(self,url):
        response = requests.get(url)
        #return response.content
        return response.text

    # interpret content of url to find function prototype
    def get_prototype(self,url):
        # get page from url
        page = self.get_web_page(url)
        # parse page to find protorype
        prototype = page.split("C_prototype")[1].split("<pre>")[1].split("</pre>")[0]
        return prototype

    # query google for search urls
    def query_url(self,name):
        # search itself
        urls = [url for url in search(name+" cplusplus", stop=1)]
        if len(urls)!=0:
            # get only the first result
            return urls[0]
        return None

    # C++ libs are in the form cstdlib, so ignore the first "c" letter
    def get_C_lib_from_cpp(self,lib):
        return lib[1:]

    # get lib name from url
    def get_lib_from_url(self,url):
        if url is not None and url!="":
            # split url to get the lib field
            lib_name_field = url.split("/")[-3]
            if lib_name_field.startswith("c"):
                # append the header (.h) extension
                # C++ lib case
                return self.get_C_lib_from_cpp(lib_name_field)+".h"
            # C lib case
            return lib_name_field+".h"
        return None

    # generic method to retrieve a function
    def get_function(self,name):
        # first, search current database
        f = self.query_function_db(name)
        if f is not None:
            return f
        # if not found, search on the internet
        f = self.query_function(name)
        if f is not None:
            # after finding, store
            self.store_db(f)
        return f

    # query function database
    def query_function_db(self,name):
        for f in self.db:
            if name in f.get_name():
                return f
        return None

    # query function on Internet
    def query_function(self,name):
        if name is not None and name!="":
            # query google for the url
            url = self.query_url(name)
            # get lib name from the serach url
            lib = self.get_lib_from_url(url)
            # get prototype from the page content
            prototype = self.get_prototype(url)
            # build function object
            f = External_Function(name,lib,prototype)
            return f
        return None
        
# direct call, used for testing purposes, instantiate the object
if __name__ == "__main__":
    # try to instantiate the manager
    try:
        im = Introspection_Manager()
    except:
        print("Instantiation Error")
        sys.exit(0)
    
    # check if arguments were passed
    if len(sys.argv)<2:
        print("Please, provide arguments")
        sys.exit(0)
    
    # query the given argument
    try:
        func = im.get_function(sys.argv[1])
        if func is not None:
            func.show()
    except:
        print("Function Retrieval Error")
        sys.exit(0)
