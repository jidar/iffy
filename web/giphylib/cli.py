#! /usr/bin/python

import argparse
import client
import prettytable
from collections.abc import MutableMapping
import re


class dispatch(object):

    @classmethod
    def search(cls, args):
        g = client.Giphy(args.apikey)
        r = g.api.search(
            args.query, limit=args.limit, offset=args.offset,
            rating=args.rating, lang=args.lang, random_id=args.random_id)
        data = r.json()
        if data.get('meta') and args.debug:
            print(cls._derive_prettytable(data['meta']))
        if data.get('pagination'):
            print(cls._derive_prettytable(data['pagination']))
        if data.get('data'):
            new_data = []
            for d in data['data']:
                new_data.append(
                    dict(
                        bitly_url=d['bitly_url'],
                        id=d['id'],
                        rating=d['rating'],
                        title=d['title'],
                        type=d['type']
                    ))
            data['data'] = new_data
            print(cls._derive_prettytable(data['data']))

    @classmethod
    def get(cls, args):
        g = client.Giphy(args.apikey)
        r = g.api.get(args.id, random_id=args.random_id)
        data = r.json()
        if data.get('meta') and args.debug:
            print(cls._derive_prettytable(data['meta']))
        if data.get('data'):
            d=data['data']
            new_data = dict(
                bitly_url=d['bitly_url'],
                id=d['id'],
                rating=d['rating'],
                title=d['title'],
                type=d['type']
            )
            if args.image_type:
                image_data  = dict(images= {args.image_type:data['data']['images'][args.image_type]})
            print(cls._derive_prettytable(new_data))
            print(cls._derive_prettytable(image_data))
        # if data.get('meta'):
        #     print(cls._derive_prettytable(data['meta']))


    @classmethod
    def _derive_prettytable(cls, jsonobj):
        """
        Given a datastructure generated by json.loads(), derives and returns a prettytable.
        """
        table = prettytable.PrettyTable()

        # assumes a dict or a list of dicts
        field_names = []
        if isinstance(jsonobj, list):
            flat_jobj_list = list()
            for item in jsonobj:
                flat_jobj = cls._flatten(item)
                flat_jobj_list.append(flat_jobj)
                field_names.extend(list(flat_jobj.keys()))
            jsonobj = flat_jobj_list
            field_names = list(set(field_names))
        elif isinstance(jsonobj, dict):
            jsonobj = cls._flatten(jsonobj)
            field_names = list(jsonobj.keys())
        else:
            raise Exception(
                "Unsupported response object, cannot derive table: {}".format(str(jsonobj)))

        # Generate and sort column headers alphabetically
        field_names = list(set(field_names))
        field_names.sort()

        # If there's a single `id` field, put that first
        uuid_header = [s for s in field_names if re.search(r"^\w+\.id$", s)]
        if len(uuid_header) == 1:
            uuid_header = uuid_header[0]
            field_names.remove(uuid_header)
            field_names.insert(0, uuid_header)

        table.field_names = field_names
        if isinstance(jsonobj, list):
            for item in jsonobj:
                row_data = []
                for name in field_names:
                    row_data.append(str(item.get(name)))
                table.add_row(row_data)
        else:
            row_data = []
            for name in field_names:
                row_data.append(str(jsonobj.get(name)))
            table.add_row(row_data)

        if len(table._rows) == 0:
            return None

        return table

    @classmethod
    def _flatten(cls, d, parent_key='', sep='.'):
        """
        Convert a datastructure of nested dictionaries to a single flat dictionary,
        where the keys are dot-separated paths to the location of the data in the original nested
        datastructure.
        """
        items = []
        for k, v in d.items():
            new_key = parent_key + sep + k if parent_key else k
            if isinstance(v, MutableMapping):
                items.extend(cls._flatten(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)

def cli():
    parser = argparse.ArgumentParser()
    #parser.set_defaults(func=help)
    parser.add_argument('apikey')
    subparsers = parser.add_subparsers()

    search_parser = subparsers.add_parser("search")
    search_parser.set_defaults(func=dispatch.search)
    search_parser.add_argument('query')
    search_parser.add_argument('--limit')
    search_parser.add_argument('--offset')
    search_parser.add_argument('--rating')
    search_parser.add_argument('--lang')
    search_parser.add_argument('--random-id')
    search_parser.add_argument('--debug', action='store_true')

    get_parser = subparsers.add_parser("get")
    get_parser.set_defaults(func=dispatch.get)
    get_parser.add_argument('id')
    get_parser.add_argument('--random-id')
    get_parser.add_argument(
        '--image-type',
        choices=[
        'fixed_height',
        'fixed_height_still',
        'fixed_height_downsampled',
        'fixed_width',
        'fixed_width_still',
        'fixed_width_downsampled',
        'fixed_height_small',
        'fixed_height_small_still',
        'fixed_width_small',
        'fixed_width_small_still',
        'downsized',
        'downsized_still',
        'downsized_large',
        'downsized_medium',
        'downsized_small',
        'original',
        'original_still',
        'looping',
        'preview',
        'preview_gif'])
    get_parser.add_argument('--debug', action='store_true')

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)

if __name__ == "__main__":
    cli()