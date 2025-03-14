<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
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
    public function register(RegisterRequest $request)
    {
        $validated = $request->validated();
        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => Hash::make(value: $validated['password']),    
        ]);

        $this->send_code($user);

        return response()->json([
            'message' => 'Verification code sent to your email.'
        ], 201);
    }

    protected function send_code(User $user)
    {
        $code = rand(100000, 999999);

        $user->notify(new VerificationCodeNotification($code));
        Cache::put("auth:otp:$user->id", $code, now()->addMinutes(5));
    }

    public function verify_code(Request $request)
    {
        $validated = $request->validate([
            'code' => ['required', 'digits:6'],
            'email' => ['required','email', 'max:255'],
        ]);
        $user = User::where('email', $validated['email'])->first();
        if (!$user) {
            return response()->json([
                'message' => 'User not found.',
            ], 404);
        }
        $cached_code = Cache::get("auth:otp:$user->id");
        if ($cached_code && (int) $request['code'] == $cached_code)
        {
            Cache::forget("auth:otp:$user->id");

            $user->email_verified_at = now();
            $user->save();
            $token = $user->createToken('authToken')->plainTextToken;

            return response()->json([
                'token' => $token
            ], 200);
        }
        return response()->json([
            'message' => 'Verification code is invalid.',
        ], 400);
    }

    public function login(LoginRequest $request)
    {
        $validated = $request->validated();
        if (Auth::attempt(['email' => $validated['email'], 'password' => $validated['password']]))
        {
            $user = Auth::user();
            if (!$user->hasVerifiedEmail())
            {
                $this->send_code($user);
                
                return response()->json([
                    'message' => 'Verification code sent to your email.',
                ], 201);
            }
            $token = $user->createToken('authToken')->plainTextToken;
            return response()->json([
                'message' => 'Login Successfully',
                'token' => $token
            ], 200);
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
