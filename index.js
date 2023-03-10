import pg from "pg";
import { createHmac } from "crypto";
const Pool = pg.Pool;
/**
 * @fileoverview a small shell for the pg package
 * @author DewArt Studio
 * @class
 */
class DewartPG {
    /**
     * Creates an object to work with the database
     * @param {Object} input input data
     * @param {Object} input.configs connection configuration object
     * @param {String} input.configs.host database host
     * @param {String} input.configs.port the port that postgres listens to
     * @param {String} input.configs.database name of the database
     * @param {String} input.configs.user database user name
     * @param {String} input.configs.password password of the database user
     * @param {Number} input.configs.idleTimeoutMillis
     * @param {Number} input.configs.connectionTimeoutMillis
     * @param {Object} input.hash configuration object for the hash function
     * @param {String} input.hash.secret secret key
     * @param {String} input.hash.algorithm hashing algorithm
     */
    constructor(input) {
        this._configs = input;
        this._pool = new Pool(input.configs);
    }

    /**
     * closes database connections
     */
    close(callback) {
        this._pool.end(() => {
            if (callback !== undefined) callback();
        });
    }

    /**
     * Performs an async query to the database
     * @param {String} query database query
     * @param {Array<String>} values query values
     * @param {function} callback database query the query result handler can accept the query result
     * @param {function} error the error handler can accept an error
     * @returns {Object} can return the result of the callback function
     */
    query(query, values, callback, error) {
        this._pool.connect((err, client, release) => {
            if (err) return error(err);
            client.query(query, values, (err, result) => {
                release();
                if (err && typeof err === "function") return error(err);
                if (typeof callback === "function") return callback(result);
            });
        });
    }

    /**
     * Performs an sync query to the database
     * @param {String} query database query
     * @param {Array<String>} values query values
     */
    async querySync(query, values) {
        let client, result;
        try {
            client = await this._pool.connect();
            try {
                result = await client.query(query, values);
                client.release();
                return result;
            } catch (err) {
                console.error("Ошибка выполнения запроса", err.stack);
            }
        } catch (err) {
            console.error("Ошибка получения клиента", err.stack);
        }
        return false;
    }

    /**
     * Executes a synchronous query to the database. Additionally, the required fields create a hash
     *
     * For example:
     *
     * params = {login: 'value'};
     *
     * query = "SELECT * FROM table_name WHERE {%login%} = \'{&login&}\'"
     *
     * result query = "SELECT * FROM table_name WHERE login = $1" ['hash of the word login']
     * @param {Object} params value object {hash{...},other{...}}
     * @param {Object} params.hash the fields of this object must contain strings that need to be hashed
     * @param {Object} params.other the fields of this object must contain strings that need to be hashed
     * @param {String} query database query
     * @param {function} callback database query the query result handler can accept the query result
     * @param {function} error the error handler can accept an error
     */
    hashQuery(params, query, callback, error) {
        try {
            if (this._configs === undefined || this._configs.hash.secret === undefined)
                throw Error("The object's configurations do not contain a secret key for encryption. Add an object to the object's constructor: \nconst options = {\n   cryptoKey: '<values>'\n}\nlet dpg = new Postgres(options)\n\n");
            params = this._prepareHashParams(params);

            let counter = 0;
            let values = [];
            for (let i = 0; i < params.length; i++) {
                query = query.replace(new RegExp(`{%${params[i].name}%}`, "g"), params[i].name).replace(new RegExp(`{&${params[i].name}&}`, "g"), `$${++counter}`);
                values.push(params[i].value);
            }
            this.query(query, values, callback, error);
        } catch (err) {
            if (err && typeof err === "function") return error(err);
        }
    }

    /**
     * Executes a synchronous query to the database. Additionally, the required fields create a hash
     *
     * For example:
     *
     * params = {login: 'value'};
     *
     * query = "SELECT * FROM table_name WHERE {%login%} = \'{&login&}\'"
     *
     * result query = "SELECT * FROM table_name WHERE login = $1" ['hash of the word login']
     * @param {Object} params value object {hash{...},other{...}}
     * @param {Object} params.hash the fields of this object must contain strings that need to be hashed
     * @param {Object} params.other the fields of this object must contain strings that need to be hashed
     * @param {String} query database query
     */
    async hashQuerySync(params, query) {
        try {
            if (this._configs === undefined || this._configs.hash.secret === undefined)
                throw Error("The object's configurations do not contain a secret key for encryption. Add an object to the object's constructor: \nconst options = {\n   cryptoKey: '<values>'\n}\nlet dpg = new Postgres(options)\n\n");
            params = this._prepareHashParams(params);
            let counter = 0;
            let values = [];
            for (let i = 0; i < params.length; i++) {
                query = query.replace(new RegExp(`{%${params[i].name}%}`, "g"), params[i].name).replace(new RegExp(`{&${params[i].name}&}`, "g"), `$${++counter}`);
                values.push(params[i].value);
            }
            return await this.syncQuery(query, values);
        } catch (err) {
            console.log(err);
        }
    }

    /**
     * @ignore
     * @private
     */
    _prepareHashParams(params) {
        let result = [];
        console.log(params);
        if (params.hash !== undefined) {
            let keys = Object.keys(params.hash);
            for (let i = 0; i < keys.length; i++) {
                result.push({
                    name: keys[i],
                    value: this._hash(params.hash[keys[i]]),
                });
            }
        }
        if (params.other !== undefined) {
            let keys = Object.keys(params.other);
            for (let i = 0; i < keys.length; i++) {
                result.push({
                    name: keys[i],
                    value: params.other[keys[i]],
                });
            }
        }

        return result;
    }
    /**
     * @ignore
     * @private
     */
    _hash(value) {
        if (this._configs === undefined || this._configs.hash.secret === undefined || this._configs.hash.algorithm === undefined)
            throw Error(
                "The object's configurations do not contain a secret key or algorithm for encryption. Add an configs to the class's constructor: \nconst options = {\n   configs: {...},\n   hash: {\n      secret: '<value>', \n      algorithm: '<value>'\n   }\n}\nlet dpg = new Postgres(options)\n\n"
            );
        return createHmac(this._configs.hash.algorithm, this._configs.hash.secret).update(value).digest("hex");
    }
}
