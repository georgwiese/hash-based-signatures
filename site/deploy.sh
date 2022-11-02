wasm-pack build --target web && wasm-pack build --target bundler

cd site
rm -r dist
npm install
npx webpack
cp index.html dist/

cd ..

git commit -am "Update webapp"
git push origin `git subtree split --prefix site/dist`:webapp --force