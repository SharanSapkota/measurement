import datetime
import hashlib
import os
import random
import secrets
from functools import wraps

from flask import Flask, Response, request
from flask_caching import Cache
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from jsonschema import ValidationError, draft7_format_checker, validate
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import BadRequest, Conflict, Forbidden, NotFound, UnsupportedMediaType
from werkzeug.routing import BaseConverter


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///sensorhub.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["CACHE_TYPE"] = "SimpleCache"

db = SQLAlchemy(app)
api = Api(app)
cache = Cache(app)


class Sensor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    model = db.Column(db.String(64), nullable=False)

    measurements = db.relationship(
        "Measurement",
        back_populates="sensor",
        cascade="all, delete-orphan"
    )
    api_key = db.relationship(
        "ApiKey",
        back_populates="sensor",
        uselist=False,
        cascade="all, delete-orphan"
    )

    def serialize(self):
        return {
            "name": self.name,
            "model": self.model
        }

    def deserialize(self, doc):
        self.name = doc["name"]
        self.model = doc["model"]

    @staticmethod
    def json_schema():
        schema = {
            "type": "object",
            "required": ["name", "model"]
        }
        props = schema["properties"] = {}
        props["name"] = {
            "type": "string",
            "description": "Unique sensor name"
        }
        props["model"] = {
            "type": "string",
            "description": "Sensor model"
        }
        return schema


class Measurement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time = db.Column(db.DateTime, nullable=False)
    value = db.Column(db.Float, nullable=False)

    sensor_id = db.Column(db.Integer, db.ForeignKey("sensor.id"), nullable=False)
    sensor = db.relationship("Sensor", back_populates="measurements")

    def serialize(self):
        return {
            "time": self.time.isoformat(),
            "value": self.value
        }

    def deserialize(self, doc):
        self.time = datetime.datetime.fromisoformat(doc["time"])
        self.value = doc["value"]

    @staticmethod
    def json_schema():
        schema = {
            "type": "object",
            "required": ["time", "value"]
        }
        props = schema["properties"] = {}
        props["time"] = {
            "type": "string",
            "format": "date-time"
        }
        props["value"] = {
            "type": "number"
        }
        return schema


class ApiKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.LargeBinary(32), nullable=False, unique=True)
    sensor_id = db.Column(db.Integer, db.ForeignKey("sensor.id"), nullable=True)
    admin = db.Column(db.Boolean, default=False)

    sensor = db.relationship("Sensor", back_populates="api_key")

    @staticmethod
    def key_hash(key):
        return hashlib.sha256(key.encode()).digest()


class SensorConverter(BaseConverter):
    def to_python(self, sensor_name):
        db_sensor = Sensor.query.filter_by(name=sensor_name).first()
        if db_sensor is None:
            raise NotFound
        return db_sensor

    def to_url(self, db_sensor):
        return db_sensor.name


app.url_map.converters["sensor"] = SensorConverter


def require_admin(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        key = request.headers.get("Sensorhub-Api-Key")
        if not key:
            raise Forbidden

        key_hash = ApiKey.key_hash(key)
        db_key = ApiKey.query.filter_by(admin=True).first()
        if db_key is not None and secrets.compare_digest(key_hash, db_key.key):
            return func(*args, **kwargs)
        raise Forbidden

    return wrapper


def require_sensor_key(func):
    @wraps(func)
    def wrapper(self, sensor, *args, **kwargs):
        key = request.headers.get("Sensorhub-Api-Key")
        if not key:
            raise Forbidden

        key_hash = ApiKey.key_hash(key)
        db_key = ApiKey.query.filter_by(sensor=sensor).first()
        if db_key is not None and secrets.compare_digest(key_hash, db_key.key):
            return func(self, sensor, *args, **kwargs)
        raise Forbidden

    return wrapper


class SensorCollection(Resource):
    def get(self):
        sensors = Sensor.query.all()
        return [sensor.serialize() for sensor in sensors]

    @require_admin
    def post(self):
        if not request.is_json:
            raise UnsupportedMediaType

        try:
            validate(request.json, Sensor.json_schema())
        except ValidationError as e:
            raise BadRequest(description=str(e))

        sensor = Sensor()
        sensor.deserialize(request.json)

        try:
            db.session.add(sensor)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            raise Conflict(
                description="Sensor with name '{name}' already exists.".format(**request.json)
            )

        return Response(
            status=201,
            headers={"Location": api.url_for(SensorItem, sensor=sensor)}
        )


class SensorItem(Resource):
    def get(self, sensor):
        return sensor.serialize()

    @require_admin
    def put(self, sensor):
        if not request.is_json:
            raise UnsupportedMediaType

        try:
            validate(request.json, Sensor.json_schema())
        except ValidationError as e:
            raise BadRequest(description=str(e))

        sensor.deserialize(request.json)

        try:
            db.session.add(sensor)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            raise Conflict(
                description="Sensor with name '{name}' already exists.".format(**request.json)
            )

        return Response(status=204)

    @require_admin
    def delete(self, sensor):
        db.session.delete(sensor)
        db.session.commit()
        return Response(status=204)


class MeasurementCollection(Resource):
    def get(self, sensor):
        body = {
            "sensor": sensor.name,
            "measurements": [m.serialize() for m in sensor.measurements]
        }
        return body

    @require_sensor_key
    def post(self, sensor):
        if not request.is_json:
            raise UnsupportedMediaType

        try:
            validate(
                request.json,
                Measurement.json_schema(),
                format_checker=draft7_format_checker
            )
        except ValidationError as e:
            raise BadRequest(description=str(e))

        measurement = Measurement()
        measurement.deserialize(request.json)
        measurement.sensor = sensor

        try:
            db.session.add(measurement)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            raise Conflict(description="Measurement could not be created.")

        return Response(
            status=201,
            headers={
                "Location": api.url_for(
                    MeasurementItem,
                    sensor=sensor,
                    measurement=measurement.id
                )
            }
        )


class MeasurementItem(Resource):
    @require_admin
    def delete(self, sensor, measurement):
        db_measurement = Measurement.query.filter_by(id=measurement, sensor=sensor).first()
        if db_measurement is None:
            raise NotFound

        db.session.delete(db_measurement)
        db.session.commit()
        return Response(status=204)


api.add_resource(SensorCollection, "/api/sensors/")
api.add_resource(SensorItem, "/api/sensors/<sensor:sensor>/")
api.add_resource(MeasurementCollection, "/api/sensors/<sensor:sensor>/measurements/")
api.add_resource(MeasurementItem, "/api/sensors/<sensor:sensor>/measurements/<int:measurement>/")


def db_init():
    db.create_all()

    if Sensor.query.first() is not None:
        return

    for idx, letter in enumerate("ABC", start=1):
        sensor = Sensor(
            name=f"sensor-{letter}",
            model="test-sensor"
        )
        db.session.add(sensor)
        db.session.flush()

        sensor_token = secrets.token_urlsafe(24)
        db_key = ApiKey(
            key=ApiKey.key_hash(sensor_token),
            sensor=sensor,
            admin=False
        )
        db.session.add(db_key)

        now = datetime.datetime.now(datetime.timezone.utc)
        interval = datetime.timedelta(seconds=10)
        for _ in range(5):
            meas = Measurement(
                value=round(random.random() * 100, 2),
                time=now
            )
            now += interval
            sensor.measurements.append(meas)

        print(f"Sensor key for {sensor.name}: {sensor_token}")

    db.session.commit()


@app.route("/")
def home():
    return {"message": "Sensorhub API is running"}


@app.route("/init-db")
def init_db_route():
    db.create_all()
    db_init()
    return {"message": "database initialized"}


@app.route("/generate-master-key")
def generate_master_key_route():
    db.create_all()
    token = secrets.token_urlsafe(32)
    db_key = ApiKey(
        key=ApiKey.key_hash(token),
        admin=True
    )
    db.session.add(db_key)
    db.session.commit()
    return {"apikey": token}


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))