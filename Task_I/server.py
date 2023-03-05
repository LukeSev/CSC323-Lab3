import web
from web import form
import crypto, os, random

master_key = os.urandom(16)
secrets = open("static/goodlife.txt", "r").readlines()
secret = secrets[random.randint(0,len(secrets)-1)].rstrip("\n")

render = web.template.render('templates/')
urls = ('/', 'index',
        '/submit', 'submit',
        '/eavesdrop', 'eavesdrop')

class index:

    def GET(self):
        user_data = web.input(enc="")
        if verify_decrypt(user_data.enc):
            return web.notfound()
        else:
            return web.forbidden()

class eavesdrop:

    def GET(self):
        msg = crypto.cbc_encrypt(secret, master_key).hex()
        return render.generic(form.Form(),"You eavesdropped the following message:",msg,False)

class submit:
    myform = form.Form(
        form.Textbox("guess",
            form.notnull,
            description = "Your Guess"),
        form.Button("Submit",
            description="Submit"))

    def GET(self):
        return render.generic(self.myform(), "Enter the plaintext.", "", False)


    def POST(self):
        if not self.myform.validates():
            return render.generic(self.myform(), "", "Invalid form data.", False)
        if self.myform.d.guess == secret:
            return render.generic(self.myform(), "Correct!", "", True)
        return render.generic(self.myform(), "", "Try again!", False)

    

def verify_decrypt(enc):

    if enc == None or enc == "":
        return False
    try:
        plain = crypto.cbc_decrypt(bytes.fromhex(enc), master_key)
        return True
    except:
        return False

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()