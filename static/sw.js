self.addEventListener("push", e => {
    let d = { title: "The Samaritan", body: "New notification", url: "/" };
    if (e.data) try { d = { ...d, ...e.data.json() }; } catch {}
    e.waitUntil(self.registration.showNotification(d.title, { body: d.body, data: { url: d.url } }));
});
self.addEventListener("notificationclick", e => {
    e.notification.close();
    const u = (e.notification.data && e.notification.data.url) || "/";
    e.waitUntil(clients.matchAll({ type: "window", includeUncontrolled: true }).then(list => {
        for (const c of list) if ("focus" in c) return c.focus();
        if (clients.openWindow) return clients.openWindow(u);
    }));
});
