import { NextRequest, NextResponse } from 'next/server';
import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

const client = jwksClient({
    jwksUri: process.env.JWKS_URI || ''
});

function getKey(header: any, callback: any) {
    client.getSigningKey(header.kid, function (err, key: any) {
        const signingKey = key.getPublicKey();
        callback(null, signingKey);
    });
}

export async function GET(req: NextRequest) {
    const token = req.headers.get('authorization')?.replace('Bearer ', '');
    if (!token) return NextResponse.json({ error: 'No token' }, { status: 401 });

    return new Promise((resolve) => {
        jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
            if (err) {
                resolve(NextResponse.json({ error: 'Invalid token' }, { status: 401 }));
            } else {
                resolve(NextResponse.json({ user: decoded }));
            }
        });
    });
}