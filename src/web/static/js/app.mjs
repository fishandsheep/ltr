import { render } from './vendor/preact.mjs';
import { html } from './lib.mjs';
import App from './components/App.mjs';

render(html`<${App} />`, document.getElementById('app'));
