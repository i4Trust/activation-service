from flask import current_app
db = current_app.config['db']

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    eori = db.Column(db.String(150), nullable=False)
    access_token = db.Column(db.Text, nullable=False, unique=True)
    expires = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return 'eori={}, access_token={}, expires={}'.format(self.eori, self.access_token[:20]+"...", self.expires)
