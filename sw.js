/* ÜSTAD KENAN — SİBER GÜVENLİK 3D MERKEZ · Service Worker (çevrimdışı destek) */
var ONBELLEK = 'ustad-cyber-v31';
var YEREL = [
  './',
  './index.html',
  './manifest.json',
  './assets/foto/kenan-avatar.jpg',
  './assets/foto/ataturk-bayrakli.jpg',
  './assets/icons/uygulama-192.png',
  './assets/icons/uygulama-512.png',
  './assets/icons/whatsapp.svg',
  './assets/icons/instagram.svg',
  './assets/icons/youtube.svg',
  './assets/icons/tiktok.svg',
  './assets/icons/facebook.svg',
  './assets/icons/linkedin.svg',
  './assets/icons/gmail.svg'
];

self.addEventListener('install', function(e){
  e.waitUntil(
    caches.open(ONBELLEK).then(function(c){
      return Promise.all(YEREL.map(function(u){
        return c.add(u).catch(function(){ /* eksik dosya ön belleği bozmasın */ });
      }));
    }).then(function(){ return self.skipWaiting(); })
  );
});

self.addEventListener('activate', function(e){
  e.waitUntil(
    caches.keys().then(function(anahtarlar){
      return Promise.all(anahtarlar.map(function(k){
        if(k !== ONBELLEK) return caches.delete(k);
      }));
    }).then(function(){ return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function(e){
  var istek = e.request;
  if(istek.method !== 'GET') return;

  var url;
  try{ url = new URL(istek.url); }catch(h){ return; }

  /* Dış siteler (CDN, yayın, API): doğrudan ağdan */
  if(url.origin !== location.origin) return;

  /* Sayfa açılışı: önce ağ (yeni sürüm hemen gelsin), olmazsa ön bellek */
  if(istek.mode === 'navigate'){
    e.respondWith(
      fetch(istek).then(function(c){
        var kopya = c.clone();
        caches.open(ONBELLEK).then(function(c2){ c2.put('./index.html', kopya); });
        return c;
      }).catch(function(){
        return caches.match('./index.html').then(function(c){ return c || caches.match('./'); });
      })
    );
    return;
  }

  /* Yerel dosyalar: ön bellekten ver, arka planda tazele */
  e.respondWith(
    caches.match(istek).then(function(onbellekCevap){
      if(onbellekCevap){
        fetch(istek).then(function(taze){
          if(taze && taze.ok) caches.open(ONBELLEK).then(function(c){ c.put(istek, taze); });
        }).catch(function(){});
        return onbellekCevap;
      }
      return fetch(istek).then(function(c){
        if(c && c.ok && c.type === 'basic'){
          var kopya = c.clone();
          caches.open(ONBELLEK).then(function(c2){ c2.put(istek, kopya); });
        }
        return c;
      }).catch(function(){
        return caches.match('./index.html');
      });
    })
  );
});
