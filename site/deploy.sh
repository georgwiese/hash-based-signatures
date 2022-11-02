cd site
npx webpack
cp index.html dist/

cd ..

git commit -am "Update webapp"
git subtree push --prefix dist origin webapp