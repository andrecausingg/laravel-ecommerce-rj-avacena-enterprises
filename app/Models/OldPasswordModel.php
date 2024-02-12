<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class OldPasswordModel extends Model
{
    use HasFactory;
    protected $table = 'users_old_pass_tbl';
    protected $primaryKey = 'id';
    protected $fillable = [
        'user_id_hash',
        'password',
    ];
}
