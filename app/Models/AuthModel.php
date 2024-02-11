<?php

namespace App\Models;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Tymon\JWTAuth\Contracts\JWTSubject;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class AuthModel extends Authenticatable implements JWTSubject, MustVerifyEmail
{
    use HasFactory;
    protected $table = 'users_tbl';
    protected $primaryKey = 'id';
    protected $fillable = [
        'id_hash',
        'phone_number',
        'email',
        'password',
        'role',
        'status',
        'verification_number',
        'verification_key',
        'phone_verified_at',
        'email_verified_at',
        'update_password_at',
    ];

    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getAttribute('id_hash');
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [];
    }

    /**
     * Get the name of the unique identifier for the user.
     *
     * @return string
     */
    public function getAuthIdentifierName()
    {
        return 'id_hash';
    }
}
