async function submit_secret_credentials() {
    const issued = await fetch('InsecureLogin/credentials', {
        method: 'POST',
        credentials: 'same-origin',
        cache: 'no-store'
    });
    if (!issued.ok) return;

    const credentials = await issued.json();
    await fetch('InsecureLogin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        cache: 'no-store',
        body: JSON.stringify(credentials)
    });
}
