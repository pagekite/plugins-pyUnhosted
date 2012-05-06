bin/Unhosted.combined.py: Unhosted.py ../HttpdLite/HttpdLite.py
	breeder ../HttpdLite/HttpdLite.py Unhosted.py >bin/Unhosted.combined.py
	chmod +x bin/Unhosted.combined.py

clean:
	rm -f bin/*.combined.py *.pyc
