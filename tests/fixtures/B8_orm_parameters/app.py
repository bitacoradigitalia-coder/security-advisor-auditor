x = input()
User.query.filter_by(name=x).first()
