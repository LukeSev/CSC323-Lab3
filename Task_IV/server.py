import web
import crypto

hmac = crypto.HMAC()
#print hmac.mac_query("test")

render = web.template.render('templates/')
urls = ('/', 'index')

class index:

	def GET(self):
		user_data = web.input(q="",mac="")
		
		if user_data.q == "" or user_data.mac == "":
			return render.generic("", "Invalid signature.", False)
		try:
			int(user_data.mac, 16)
		except:
			return render.generic("", "Signature must be in hex.", False)
		
		if hmac.verify_query(user_data.q, user_data.mac):
			return render.generic("Correct!", "", True)
		else:
			return render.generic("", "Invalid signature.", False)
			

if __name__ == "__main__":
	app = web.application(urls, globals())
	app.run()