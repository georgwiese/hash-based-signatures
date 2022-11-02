cd site
npm install
npx webpack
cp index.html dist/

cd ..

git commit -am "Update webapp"
git subtree push --prefix site/dist origin webapp