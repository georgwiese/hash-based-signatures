wasm-pack build --target web && wasm-pack build --target bundler

cd site
npm install
npx webpack
cp index.html dist/

cd ..

cargo doc
cp -r target/doc site/dist/docs

git commit -am "Update webapp"
git subtree push --prefix site/dist origin webapp