<?php

namespace App\Http\Controllers;

use App\Models\RefreshToken;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Carbon\Carbon;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Auth;

class TokenController extends Controller
{
    /**
     * Create a new refresh token
     *
     * @param int $userId
     * @param Request|null $request
     * @return RefreshToken
     */
    public function createRefreshToken(int $userId, ?Request $request = null): RefreshToken
    {
        return RefreshToken::create([
            'user_id' => $userId,
            'token' => hash('sha256', Str::random(60)),
            'expires_at' => Carbon::now()->addDays(30),
            'device_info' => $request?->userAgent(),
            'created_ip' => $request?->ip()
        ]);
    }

    /**
     * Refresh the access token using a refresh token
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function refresh(Request $request): JsonResponse
    {
        try {
            if (!$request->has('refresh_token')) {
                return response()->json([
                    'success' => false,
                    'message' => 'Refresh token is required'
                ], 400);
            }

            $refreshToken = RefreshToken::where('token', $request->refresh_token)
                ->where('revoked', false)
                ->first();

            if (!$refreshToken) {
                return response()->json([
                    'success' => false,
                    'message' => 'Invalid refresh token'
                ], 401);
            }

            if (!$refreshToken->isValid()) {
                $refreshToken->update(['revoked' => true]);
                return response()->json([
                    'success' => false,
                    'message' => 'Refresh token has expired'
                ], 401);
            }

            // Generate new access token
            $user = $refreshToken->user;
            $token = JWTAuth::fromUser($user);
            
            // Revoke old refresh token and create new one
            $refreshToken->update(['revoked' => true]);
            $newRefreshToken = $this->createRefreshToken($user->id, $request);

            return response()->json([
                'success' => true,
                'access_token' => $token,
                'token_type' => 'bearer',
                'expires_in' => config('jwt.ttl') * 60,
                'refresh_token' => $newRefreshToken->token
            ]);

        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Could not refresh token'
            ], 500);
        }
    }

    /**
     * Revoke a refresh token
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function revokeToken(Request $request): JsonResponse
    {
        try {
            if ($request->has('refresh_token')) {
                RefreshToken::where('token', $request->refresh_token)
                    ->update(['revoked' => true]);
            }

            return response()->json([
                'success' => true,
                'message' => 'Token revoked successfully'
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Could not revoke token'
            ], 500);
        }
    }

    /**
     * Get all active refresh tokens for the authenticated user
     *
     * @return JsonResponse
     */
    public function getActiveTokens(): JsonResponse
    {
        try {
            $tokens = RefreshToken::where('user_id', Auth::id())
                ->where('revoked', false)
                ->where('expires_at', '>', Carbon::now())
                ->get(['id', 'device_info', 'created_ip', 'created_at', 'expires_at']);

            return response()->json([
                'success' => true,
                'tokens' => $tokens
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Could not retrieve tokens'
            ], 500);
        }
    }
}
