import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

export default async function handler(req, res) {
    // CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') return res.status(200).end();

    const action = req.query.action;

    try {
        // LOGIN
        if (action === 'login' && req.method === 'POST') {
            let body = req.body;
            if (typeof body === 'string') body = JSON.parse(body);

            const { data: user, error } = await supabase
                .from('users')
                .select('*')
                .eq('name', body.username)
                .eq('password', body.password)
                .single();

            if (error || !user) {
                return res.status(401).json({ success: false, error: 'Utilizator sau parolă incorectă' });
            }

            // Generează un token simplu
            const token = Buffer.from(JSON.stringify({ 
                id: user.id, 
                name: user.name, 
                role: user.role,
                exp: Date.now() + 24 * 60 * 60 * 1000 // 24 ore
            })).toString('base64');

            return res.json({ 
                success: true, 
                data: { 
                    token, 
                    user: { 
                        id: user.id, 
                        name: user.name, 
                        role: user.role 
                    } 
                } 
            });
        }

        // VERIFY TOKEN
        if (action === 'verify') {
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ success: false, error: 'Token lipsă' });
            }

            try {
                const token = authHeader.replace('Bearer ', '');
                const decoded = JSON.parse(Buffer.from(token, 'base64').toString());
                
                if (decoded.exp < Date.now()) {
                    return res.status(401).json({ success: false, error: 'Token expirat' });
                }

                return res.json({ 
                    success: true, 
                    data: { 
                        user: { 
                            id: decoded.id, 
                            name: decoded.name, 
                            role: decoded.role 
                        } 
                    } 
                });
            } catch (e) {
                return res.status(401).json({ success: false, error: 'Token invalid' });
            }
        }

        // LOGOUT
        if (action === 'logout') {
            return res.json({ success: true });
        }

        return res.status(400).json({ success: false, error: 'Invalid action' });

    } catch (e) {
        console.error('Auth error:', e);
        return res.status(500).json({ success: false, error: e.message });
    }
}
