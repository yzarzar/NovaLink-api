<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Tymon\JWTAuth\Facades\JWTAuth;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\GoogleProvider;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Http\JsonResponse;
use Laravel\Socialite\Two\InvalidStateException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Carbon\Carbon;

class AuthController extends Controller
{
    /**
     * Create a new token for the user
     *
     * @param User $user
     * @param Request|null $request
     * @return array
     */
    protected function createToken(User $user, ?Request $request = null): array
    {
        $token = JWTAuth::fromUser($user);
        $expiration = config('jwt.ttl');

        // Only create refresh token for regular authentication
        $refreshToken = null;
        if (!request()->is('api/auth/google/callback')) {
            $tokenController = new TokenController();
            $refreshToken = $tokenController->createRefreshToken($user->id, $request);
        }

        $response = [
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => $expiration * 60,
            'user' => $user
        ];

        // Add refresh token if it's a regular login
        if ($refreshToken) {
            $response['refresh_token'] = $refreshToken->token;
        }

        // Add Google refresh token if it exists
        if ($user->google_refresh_token) {
            $response['google_refresh_token'] = $user->google_refresh_token;
        }

        return $response;
    }

    /**
     * Register user
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function register(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $tokenData = $this->createToken($user);

        return response()->json([
            'success' => true,
            ...$tokenData
        ], 201);
    }

    /**
     * Login with email and password
     */
    public function login(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        if (!$token = Auth::attempt($validator->validated())) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid login credentials'
            ], 401);
        }

        $user = Auth::user();
        $tokenData = $this->createToken($user, $request);

        return response()->json([
            'success' => true,
            ...$tokenData
        ]);
    }

    /**
     * Redirect to Google OAuth
     *
     * @return JsonResponse
     */
    public function redirectToGoogle(): JsonResponse
    {
        /** @var GoogleProvider $provider */
        $provider = Socialite::driver('google');

        $googleUrl = $provider
            ->scopes(['openid', 'email', 'profile'])
            ->with([
                'access_type' => 'offline',
                'prompt' => 'consent select_account'
            ])
            ->redirect()
            ->getTargetUrl();

        return response()->json(['url' => $googleUrl]);
    }

    /**
     * Handle Google OAuth callback
     *
     * @return JsonResponse
     */
    public function handleGoogleCallback(): JsonResponse
    {
        try {
            /** @var GoogleProvider $provider */
            $provider = Socialite::driver('google');
            $googleUser = $provider->stateless()->user();

            if (!$googleUser->email) {
                return response()->json([
                    'success' => false,
                    'message' => 'Email is required for registration'
                ], 400);
            }

            $user = User::where('email', $googleUser->email)->first();

            if (!$user) {
                $user = User::create([
                    'name' => $googleUser->name,
                    'email' => $googleUser->email,
                    'password' => Hash::make(Str::random(16)),
                    'google_id' => $googleUser->id,
                    'google_token' => $googleUser->token,
                    //'google_refresh_token' => $googleUser->refreshToken,
                    'email_verified_at' => now(),
                ]);
            } else {
                $user->update([
                    'google_id' => $googleUser->id,
                    'google_token' => $googleUser->token,
                    // 'google_refresh_token' => $googleUser->refreshToken,
                ]);
            }

            $tokenData = $this->createToken($user);

            return response()->json([
                'success' => true,
                ...$tokenData
            ]);

        } catch (InvalidStateException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid state',
                'error' => $e->getMessage()
            ], 400);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Failed to authenticate with Google',
                'error' => $e->getMessage()
            ], 500);
        }
    }

    /**
     * Refresh expired token
     *
     * @return JsonResponse
     */
    public function refresh(): JsonResponse
    {
        try {
            $token = JWTAuth::parseToken()->refresh();
            $expiration = config('jwt.ttl');

            return response()->json([
                'success' => true,
                'access_token' => $token,
                'token_type' => 'bearer',
                'expires_in' => $expiration * 60
            ]);
        } catch (TokenExpiredException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Token has expired and can no longer be refreshed'
            ], 401);
        } catch (TokenInvalidException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid token'
            ], 401);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Could not refresh token'
            ], 500);
        }
    }

    /**
     * Get user profile
     *
     * @return JsonResponse
     */
    public function profile(): JsonResponse
    {
        try {
            $user = Auth::user();
            return response()->json([
                'success' => true,
                'user' => $user
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Unauthorized'
            ], 401);
        }
    }

    /**
     * Logout user
     */
    public function logout(Request $request): JsonResponse
    {
        try {
            if ($request->has('refresh_token')) {
                app(TokenController::class)->revokeToken($request);
            }

            Auth::logout();
            return response()->json([
                'success' => true,
                'message' => 'Successfully logged out'
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Could not log out user'
            ], 500);
        }
    }
}
