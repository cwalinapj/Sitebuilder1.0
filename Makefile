.PHONY: build test clean

build:
	python3 src/build.py

test:
	python3 -m unittest discover -s src/tests -t . -p 'test_*.py'

clean:
	rm -rf site/about site/services site/contact site/index.html site/sitemap.xml site/robots.txt site/assets
	touch site/.gitkeep
