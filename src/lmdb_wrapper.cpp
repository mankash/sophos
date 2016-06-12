//
// Sophos - Forward Private Searchable Encryption
// Copyright (C) 2016 Raphael Bost
//
// This file is part of Sophos.
//
// Sophos is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// Sophos is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Sophos.  If not, see <http://www.gnu.org/licenses/>.
//


#include "lmdb_wrapper.hpp"

#include "logger.hpp"
#include "utils.hpp"

#include <iostream>
#include <fstream>
#include <algorithm>

namespace sse {
namespace sophos {

    const std::string LMDBWrapper::data_dir = "data";
    const std::string LMDBWrapper::md_file = "info.bin";

    static void init_lmdb_struct(const std::string& db_path, const int env_flags, const mode_t mode, const bool create, MDB_env **env, MDB_dbi *dbi)
    {
        if(mdb_env_create(env) != 0)
        {
            logger::log(logger::CRITICAL) << "Unable to create an LMDB environment" << std::endl;
            exit(-1);
        }
        
        int errc = mdb_env_open(*env, db_path.c_str(), env_flags, mode);
        
        if (errc != 0) {
            logger::log(logger::CRITICAL) << "Unable to open the LMDB environment: " << LMDBWrapper::error_string(errc) << std::endl;
            exit(errc);
        }
        
        MDB_txn *txn;
        errc = mdb_txn_begin(*env, NULL, 0, &txn);
        
        if (errc != 0) {
            logger::log(logger::CRITICAL) << "Unable to create first transaction: " << LMDBWrapper::error_string(errc) << std::endl;
            exit(errc);
        }
        
        if (create) {
            errc = mdb_dbi_open(txn, NULL, MDB_CREATE, dbi);
        }else{
            errc = mdb_dbi_open(txn, NULL, 0, dbi);
        }
        
        if (errc != 0) {
            logger::log(logger::CRITICAL) << "Unable to open the database: " << LMDBWrapper::error_string(errc) << std::endl;
            exit(errc);
        }
        
        errc = mdb_txn_commit(txn);
        if (errc != 0) {
            logger::log(logger::CRITICAL) << "Unable to commit the first transaction: " << LMDBWrapper::error_string(errc) << std::endl;
            exit(errc);
        }

    }
    
    LMDBWrapper::LMDBWrapper(const std::string& db_path, const size_t setup_size, const size_t key_size, const size_t data_size) :
    env_(NULL), dbi_(0), db_path_(db_path)
    {
        if (!is_directory(db_path)) {
            throw std::runtime_error(db_path + ": not a directory");
        }
        
        std::string lmdb_data_path = db_path + "/" + data_dir;
        
        if (exists(lmdb_data_path)) {
            throw std::runtime_error("File or directory already exists at " + lmdb_data_path);
        }else{
            if (!create_directory(lmdb_data_path, (mode_t)0700)) {
                throw std::runtime_error(lmdb_data_path + ": unable to create directory");
            }

            init_lmdb_struct(lmdb_data_path, lmdb_env_flags__, lmdb_file_mode__, true, &env_, &dbi_);
            
            // set to the right size
            current_edb_size_ = setup_size * (key_size + data_size);
//            current_edb_size_ = 104857;
//            current_edb_size_ = std::max<size_t>(current_edb_size_, 1024*1024);
            
            mdb_env_set_mapsize(env_, current_edb_size_);
            
            std::string md_path = db_path + "/" + md_file;
            
            if (!write_metadata(md_path)) {
                logger::log(logger::CRITICAL) << "Unable to write the database metadata." << std::endl;
                exit(-1);
            }
        }
        
    }
    
    LMDBWrapper::LMDBWrapper(const std::string& db_path) :
    env_(NULL), dbi_(0), db_path_(db_path)
    {
        if (!is_directory(db_path)) {
            throw std::runtime_error(db_path + ": not a directory");
        }
        
        std::string lmdb_data_path = db_path + "/" + data_dir;
        init_lmdb_struct(lmdb_data_path, lmdb_env_flags__, lmdb_file_mode__, true, &env_, &dbi_);

        
        // read the meta data
        std::string md_path = db_path + "/" + md_file;

        if (!is_file(md_path)) {
            // error, the metadata file is not there
            throw std::runtime_error("Missing metadata file");
        }
        std::ifstream md_in(md_path.c_str());
        md_in >> current_edb_size_;
        
        // set to the right size
        mdb_env_set_mapsize(env_, current_edb_size_);
    }
    
    LMDBWrapper::~LMDBWrapper()
    {
        mdb_dbi_close(env_, dbi_);
        dbi_ = 0;
        
        mdb_env_close(env_);
        env_ = NULL;
    }

    bool LMDBWrapper::write_metadata(const std::string& md_path) const
    {
        std::ofstream md_out(md_path.c_str());
        if (!md_out.is_open()) {
            throw std::runtime_error(md_path + ": unable to write the metadata");
        }
        
        md_out << current_edb_size_ << std::endl;
        md_out.close();
        
        return true;
    }
    
    bool LMDBWrapper::put(const MDB_val& key, const MDB_val& val)
    {

        // create a new transaction
        MDB_txn *txn;
        int errc = mdb_txn_begin(env_, NULL, 0, &txn);
        
        if (errc != 0) {
            logger::log(logger::ERROR) << "Unable to begin transaction: " << LMDBWrapper::error_string(errc) << std::endl;
            
            return false;
        }


        errc = ::mdb_put(txn, dbi(), const_cast<MDB_val*>(&key), const_cast<MDB_val*>(&val), 0);

        if (errc == MDB_MAP_FULL) {
            // abort the transaction
            mdb_txn_abort(txn);
            txn = NULL;
            // resize
            resize();

            // re-run the transaction
            int errc = mdb_txn_begin(env_, NULL, 0, &txn);
            
            if (errc != 0) {
                logger::log(logger::ERROR) << "Unable to begin transaction: " << LMDBWrapper::error_string(errc) << std::endl;
                
                return false;
            }

            errc = ::mdb_put(txn, dbi(), const_cast<MDB_val*>(&key), const_cast<MDB_val*>(&val), 0);

            if (errc != MDB_SUCCESS) {
                logger::log(logger::CRITICAL) << "Unable to replay the transaction: "  << error_string(errc) << std::endl;
            }
        }else if(errc != MDB_SUCCESS){
            logger::log(logger::ERROR) << "Error during database put: " << error_string(errc) << std::endl;
        }

        errc = mdb_txn_commit(txn);
        
        return (errc == MDB_SUCCESS);
    }

    bool LMDBWrapper::resize()
    {
        // we need to resize the DB's map
        logger::log(logger::INFO) << "Resizing the database" << std::endl;
        
        current_edb_size_ *= (1+edb_size_increase_step__);
        // set the new size

        int errc = mdb_env_set_mapsize(env_, current_edb_size_);
        
        if (errc != 0) {
            logger::log(logger::CRITICAL) << "Error when resizing the database: " << error_string(errc) << std::endl;
            
            return false;
        }
        
        std::string md_path = db_path_ + "/" + md_file;
        return write_metadata(md_path);
        
        return true;
    }


}
}