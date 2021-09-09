<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request){
        $field = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required',
            'password' => 'required|confirmed'
        ]);

        $user = User::create([
            'name' => $field['name'],
            'email' => $field['email'],
            'password' => bcrypt($field['password']),
        ]);

        return response([
            'message' => 'User Created',
            'user' => $user
        ]);

    }

    public function login(Request $request){
        $field = $request->validate([
            'email' => 'required',
            'password' => 'required'
        ]);

        if(!Auth::attempt($request->only('email', 'password'))){
            return response([
                'message' => 'invalid credentials'
            ]);
        }
        $user = Auth::user();
        $token = $user->createToken('appToken')->plainTextToken;
        return response([
            'message' => 'Successfull',
            'token' => $token
        ])->withCookie('jwt', $token, 60*24);
    }

    public function logout(Request $request){
        $cookie = Cookie::forget('jwt');
 
        return response([
            'message' => 'success'
        ])->withCookie($cookie);
    }
    
}
