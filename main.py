import os
import datetime
import jinja2
import webapp2
import re
import random
import string
import hashlib

from google.appengine.api import memcache
from google.appengine.ext import ndb


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

class Post(ndb.Model):
    subject = ndb.StringProperty(required = True)
    content = ndb.TextProperty(required = True)
    createdDate = ndb.DateProperty(auto_now_add = True)

class UserAccount(ndb.Model):
    username = ndb.StringProperty(required = True)
    hashedPassword = ndb.StringProperty(required = True)
    email = ndb.StringProperty(required = False)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def makeSalt(self):
        result = ''
        for x in range(5):
            result += random.choice(string.ascii_letters)
        return result

    def makeHash(self, username, salt = None):
        if not salt:
            salt = self.makeSalt()
        saltedUsername = username + salt
        return '%s|%s' % (salt, hashlib.sha256(saltedUsername).hexdigest())


class BlogHandler(Handler):
    def get(self, update=False):

        key = 'landingPage'
        topTenPostsTuple = memcache.get(key)

        if topTenPostsTuple is None or update:
            topTenPosts = ndb.gql(
                "SELECT * FROM Post ORDER BY createdDate ASC LIMIT 10").fetch()
            time = datetime.datetime.utcnow()
            memcache.add(key, (topTenPosts, time))
        else:
            topTenPosts = topTenPostsTuple[0]
            time = topTenPostsTuple[1]

        cacheAge=long((datetime.datetime.utcnow() - time).total_seconds())

        self.render("landing_page.html", posts=topTenPosts, cacheAge=cacheAge)

class NewPostHandler(Handler):
    def get(self):
        self.render("new_post.html",
                    subject="",
                    subjectError="",
                    content="",
                    contentError="")

    def post(self):
        subject = self.request.get("subject")
        subjectError = ''
        content = self.request.get("content")
        contentError = ''

        if subject and content:
            newPost = Post(subject=subject,
                           content=content)
            newPostKey = newPost.put()
            postId = newPostKey.id()

            memcache.delete('landingPage')
            self.redirect("/blog/" + str(postId))

        elif not subject and not content:
            subjectError = 'Subject can not be empty!'
            contentError = 'Content can not be empty!'
        elif not subject:
            subjectError = 'Subject can not be empty!'
        else:
            contentError = 'Content can not be empty!'

        self.render("new_post.html",subject=subject,subjectError=subjectError,
            content=content,contentError=contentError)

class PostHandler(Handler):
    def get(self, url):
        postId = long(url)
        
        key = str(postId)
        cachedPost = memcache.get(key)
        if cachedPost:
            post = cachedPost[0]
            time = cachedPost[1]
        else:
            postKey = ndb.Key('Post', postId)
            post = postKey.get()
            time = datetime.datetime.utcnow()
            memcache.add(key, (post,time))

        subject = post.subject
        content = post.content
        createdDate = post.createdDate

        cacheAge=long((datetime.datetime.utcnow() - time).total_seconds())

        self.render("post.html",
                    subject=subject,
                    createdDate=createdDate,
                    content=content,
                    postId=postId,
                    cacheAge=cacheAge)

class HomePageHandler(Handler):
    def get(self):
        blog="/blog"
        self.render("homepage.html",
                    blog=blog)


class SignUpPageHandler(Handler):
    def get(self):
        self.render("signup.html",
                    username="",
                    password="",
                    verify="",
                    email="",
                    usernameError="",
                    passwordError="",
                    verifyError="",
                    emailError="")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        usernameError = ""
        passwordError = ""
        verifyError = ""
        emailError = ""
        if ( (self.validUserName(username)) and self.newUser(username) and self.validPassword(password) 
            and self.validVerification(password, verify) and self.validEmail(email) ):

            # make a hashed cookie! 
            hashedUsername = self.makeHash(username)
            self.response.headers.add_header('Set-Cookie', 'user_id=%s' % str(username))

            # persist an entity
            hashedPassword = self.makeHash(password)
            userAccount = UserAccount(username = username, hashedPassword = hashedPassword, email = email, id = username)
            userAccount.put()

            self.redirect("/welcome")

        else: 
            if(not self.newUser(username)):
                usernameError = "This username already exists."
            if(not self.validUserName(username)):
                usernameError = "That's not a valid username."
            if(not self.validPassword(password)):
                passwordError = "That wasn't a valid password."
                password = ""
                verify = ""
            if(self.validPassword(password) and not self.validVerification(password, verify)):
                verifyError = "Your passwords didn't match."
                password = ""
                verify = ""
            if(not self.validEmail(email)):
                emailError = "That's not a valid email."

            self.render("signup.html",
                        username = username,
                        password = password,
                        verify = verify,
                        email = email,
                        usernameError = usernameError,
                        passwordError = passwordError,
                        verifyError = verifyError,
                        emailError = emailError)

    def newUser(self, username):
        userKey = ndb.Key(UserAccount, username)
        user = userKey.get()
        if (user):
            return False
        else:
            return True

    def validUserName(self, user_name):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return USER_RE.match(user_name)

    def validPassword(self, pswd):
        PSWD_RE = re.compile(r"^.{3,20}$")
        return PSWD_RE.match(pswd)

    def validVerification(self, first, second):
        return first == second

    def validEmail(self, email):
        if email == "":
            return True
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        return EMAIL_RE.match(email)    

class LoginPageHandler(Handler):
    def get(self):
        self.render("login.html",
                    username="",
                    password="",
                    loginError="")
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        if(self.validLogin(username, password)):
            hashedUsername = self.makeHash(username)
            self.response.headers.add_header('Set-Cookie', 'user_id=%s' % str(username))
            self.redirect("/welcome")

        else:
            loginError = "Invalid login"
            self.render("login.html",username=username,password=password,loginError=loginError)

    def validLogin(self, username, password):
        userKey = ndb.Key(UserAccount, username)
        user = userKey.get()
        if (user):
            hashedPassword = user.hashedPassword
            salt = hashedPassword.split('|')[0]
            return hashedPassword == self.makeHash(password,salt)
        else:
            return False

class WelcomeHandler(Handler):
    def get(self):
        username = self.request.cookies.get("user_id")

        if (not username):
            self.redirect('/blog/signup')
        else:
            self.response.write("Welcome, " + username + "!")

class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=;Path=/')

        self.redirect('/blog/signup')

class FlushHandler(Handler):
    def get(self):
        memcache.flush_all()
        self.redirect("/blog")

app = webapp2.WSGIApplication([('/', HomePageHandler),
                               ('/blog', BlogHandler),
                               ('/blog/newpost', NewPostHandler),
                               ('/blog/(\d+)', PostHandler),
                               ('/login', LoginPageHandler),
                               ('/blog/signup', SignUpPageHandler),
                               ('/welcome', WelcomeHandler),
                               ('/logout', LogoutHandler),
                               ('/blog/flush', FlushHandler),
                                ],
                                debug=True)