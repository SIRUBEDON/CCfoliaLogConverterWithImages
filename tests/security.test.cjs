const test = require('node:test');
const assert = require('node:assert/strict');
const JSZip = require('jszip');
const { openSite, importFile } = require('./helpers.cjs');
const attack = '<img src="x" onerror="window.pwned=1"><svg onload="window.pwned=1"></svg><a href="javascript:window.pwned=1">bad</a><script>window.pwned=1</script>';
function hooks(source) {
  return source.replace(/\}\)\(\);\s*$/, 'window.auditHooks = { parseCocofoliaLogHtml, parseTekeyLogHtml, sanitizeMessageHtml, jsonForInlineScript, generateOutputHtml, loadProject, getData: () => displayLogData };\n})();');
}
function assertSafe(root) {
  assert.equal(root.querySelectorAll('script,svg,iframe,object,embed').length, 0);
  for (const element of root.querySelectorAll('*')) for (const a of element.attributes) {
    assert.ok(!/^on/i.test(a.name), a.name);
    if (a.name === 'href' || a.name === 'src') assert.ok(!/^\s*javascript:/i.test(a.value));
  }
}
test('HTML log import removes executable markup while preserving ruby, links and line breaks', async () => {
  const { dom, w, errors } = await openSite(hooks);
  const good = '<b>太字</b><br><ruby>漢字<rt>かんじ</rt></ruby><a href="https://example.com/">リンク</a>';
  const input = '<p><span>[main]</span><span>A:</span><span>'+good+attack+'</span></p>';
  await importFile(w, '#cocofolia-log-input', input, 'log.html');
  for (let i = 0; i < 100 && !w.document.querySelector('.bubble'); i++) await new Promise(resolve => setTimeout(resolve, 10));
  const bubble = w.document.querySelector('.bubble');
  assert.ok(bubble, errors.join('\n'));
  assertSafe(bubble);
  assert.equal(bubble.querySelector('rt').textContent, 'かんじ');
  assert.equal(bubble.querySelector('a').getAttribute('href'), 'https://example.com/');
  assert.equal(w.pwned, undefined);
  const tekey = '<div class="chatlog"><div class="tab1"><b>A:</b><span>time</span>'+good+attack+'</div></div>';
  const parsed = w.auditHooks.parseTekeyLogHtml(tekey);
  const fragment = w.document.createElement('div'); fragment.innerHTML = parsed[0].message; assertSafe(fragment);
  dom.window.close();
});
test('project imports and exported HTML do not reintroduce XSS or script-closing names', async () => {
  const { dom, w } = await openSite(hooks);
  const zip = new JSZip();
  zip.file('project_data.json', JSON.stringify({
    displayLogData: [{ type: 'message', id: 'm1', speaker: 'A', tab: 'main', originalIndex: 0, message: '<b>OK</b>'+attack }],
    characterSettings: { A: { displayName: '</script><img src=x onerror="window.pwned=1">' } }
  }));
  await w.auditHooks.loadProject(w.Uint8Array.from(await zip.generateAsync({ type: 'uint8array' })));
  const data = w.auditHooks.getData();
  const html = w.auditHooks.generateOutputHtml(data, new w.Set(['main']), {}, 'Export', { iconSize:64, normalBubbleColor:'#fff', rightBubbleColor:'#fff', baseTextColor:'#333', textEdgeColor:'#fff' });
  const output = new w.DOMParser().parseFromString(html, 'text/html');
  assert.equal(output.querySelectorAll('script').length, 1);
  for (const node of output.querySelectorAll('.bubble,.narration-message')) assertSafe(node);
  assert.ok(!output.querySelector('img[onerror*="pwned"]'));
  new w.Function(output.querySelector('script').textContent);
  const value = '</script>&<\u2028\u2029';
  assert.equal(JSON.parse(w.auditHooks.jsonForInlineScript(value)), value);
  dom.window.close();
});
test('sanitizer failure rejects rich HTML instead of accepting it', async () => {
  const { dom,w }=await openSite(hooks);
  w.DOMPurify=undefined;
  assert.throws(()=>w.auditHooks.sanitizeMessageHtml(attack));
  dom.window.close();
});
