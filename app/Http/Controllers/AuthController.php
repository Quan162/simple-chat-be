<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Notifications\VerificationCodeNotification;
use Dotenv\Parser\Parser;
use Illuminate\Http\Request;
use Illuminate\Mail\Mailable;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use PhpParser\Node\Expr\Cast\Object_;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6'
        ]);
        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password'])
        ]);

        $code = rand(100000, 999999);
        Cache::put('verification_code_' . $user->id, $code, now()->addMinutes(5));
        $user->notify(new VerificationCodeNotification($code));
        return response()->json([
            'message' => 'Verification code sent to your email.',
        ], 201);
    }
    public function verify_code(Request $request)
    {
        $validated = $request->validate([
            'code' => 'required',
            'email' => 'required|string|email|max:255'
        ]);
        $user = User::where('email', $validated['email'])->first();
        if (!$user) {
            return response()->json([
                'message' => 'User not found.',
            ], 404);
        }
        $cached_code = Cache::get('verification_code_' . $user->id);
        if ($cached_code && (int) $request['code'] == $cached_code)
        {
            Cache::forget('verification_code_' . $user->id);

            $user->email_verified_at = now();
            $user->save();
            $token = $user->createToken('authToken')->plainTextToken;

            return response()->json(['token' => $token], 200);
        }
        return response()->json([
            'message' => 'Verification code is invalid.',
            'cached_code' => $cached_code,
            'code' => (int) $request['code']
        ], 400);
    }

    public function login(Request $request)
    {
        $validated = $request->validate([
            'email' => 'required|string|email|max:255',
            'password' => 'required|string|min:6'
        ]);
        if (Auth::attempt(['email' => $validated['email'], 'password' => $validated['password']]))
        {
            $user = Auth::user();
            if (!$user->hasVerifiedEmail())
            {
                $code = rand(100000, 999999);
                Cache::put('verification_code_' . $user->id, $code, now()->addMinutes(5));
                $user->notify(new VerificationCodeNotification($code));
                return response()->json([
                    'message' => 'Verification code sent to your email.',
                ], 201);
            }
            return response()->json([
                'message' => 'You are already verified.',
            ]);
        }
        return response()->json([
            'message' => 'Invalid email or password.',
        ], 404);
    }

    public function logout(Request $request)
    {
        $request->user()->tokens()->delete();
        return response()->json(['message' => 'Successfully logged out']);
    }
}
