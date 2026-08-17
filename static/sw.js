self.addEventListener("push", (event) => {
    let data = {
        title: "The Samaritan",
        body: "You have a new notification.",
        icon: "/static/icon.png",
        url: "/",
    };
    try {
        if (event.data) data = event.data.json();
    } catch (e) {}
    const options = {
        body: data.body,
        icon: data.icon,
        badge: data.icon,
        data: { url: data.url },
        vibrate: [100, 50, 100],
    };
    event.waitUntil(self.registration.showNotification(data.title, options));
});

self.addEventListener("notificationclick", (event) => {
    event.notification.close();
    const url = event.notification.data?.url || "/";
    event.waitUntil(
        clients.matchAll({ type: "window", includeUncontrolled: true }).then((list) => {
            for (const client of list) {
                if (client.url.includes(url) && "focus" in client) return client.focus();
            }
            if (clients.openWindow) return clients.openWindow(url);
        })
    );
});
